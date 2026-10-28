"""Closed, one-operation Web API replay contract for a network-isolated worker.

Only the supervising mediator owns transport sockets and credential resolution.
The envelope is approved plan content; plan and approval digests are bound at
runtime to avoid self-referential approval material. This module grants neither
approval nor sandbox readiness and is not a CLI live-execution entry point.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from cops.evidence.canonical import canonical, digest
from cops.execution.scope_guard import ScopeGuard

from . import websocket
from .models import ReplayBudget, ReplayRequest
from .replay import DestinationGuard, StandardHttpReplayer, _ReplayDeadline, _validate_wire_request
from .sanitization import SENSITIVE_FIELD_PATTERNS

WEB_API_REPLAY_TOOL = "cops.web_api.bounded-replay-worker"
WEB_API_REPLAY_VERSION = "1"
_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_REQUEST_FIELDS = frozenset({
    "request_id", "protocol", "method", "url", "headers", "body", "graphql_query", "graphql_variables",
    "websocket_messages",
})
_BUDGET_BOUNDS = {
    "max_request_header_bytes": (1, 16384), "max_request_body_bytes": (0, 1048576),
    "max_response_header_bytes": (1, 16384), "max_output_bytes": (1, 2097152),
    "max_response_body_bytes": (0, 1048576), "max_redirect_hops": (0, 10),
    "max_websocket_frames": (2, 10000), "max_websocket_message_bytes": (1, 65536),
    "max_websocket_bytes": (10, 1048576),
}
_TRANSPORT_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "proxy-authorization", "proxy-connection", "connection",
    "upgrade", "trailer", "expect", "accept-encoding", "te",
})


class WebApiReplayError(ValueError):
    """Replay input, approval binding or peer response is outside the contract."""


def _closed(value: Any, fields: set[str] | frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WebApiReplayError(f"invalid {label} fields")
    return value


def _text(value: Any, label: str, *, maximum: int = 8192) -> str:
    if type(value) is not str or len(value) > maximum:
        raise WebApiReplayError(f"invalid {label}")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise WebApiReplayError(f"invalid {label} encoding") from None
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise WebApiReplayError(f"invalid {label}")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise WebApiReplayError(f"invalid {label} digest")
    return value


def _json(value: Any) -> str:
    # Approved ActionPlan containers are immutable mappings/tuples. Bound the
    # snapshot conversion before allocating serialized untrusted worker input.
    nodes, characters = 0, 0

    def owned(item: Any, depth: int = 0) -> Any:
        nonlocal nodes, characters
        nodes += 1
        if depth > 32 or nodes > 100000:
            raise WebApiReplayError("replay JSON structure limit exceeded")
        if isinstance(item, Mapping):
            if len(item) > 100000:
                raise WebApiReplayError("replay JSON structure limit exceeded")
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise WebApiReplayError("replay JSON keys must be strings")
                characters += len(key)
                result[key] = owned(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            if len(item) > 100000:
                raise WebApiReplayError("replay JSON structure limit exceeded")
            return [owned(child, depth + 1) for child in item]
        if type(item) is str:
            characters += len(item)
        if characters > 2097152:
            raise WebApiReplayError("replay JSON byte limit exceeded")
        return item

    try:
        return canonical(owned(value), max_bytes=2097152).decode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise WebApiReplayError("replay value must be finite JSON") from None


def _address(url: str) -> tuple[str, str, int, str]:
    _text(url, "URL")
    if (
        any(ord(char) <= 32 or ord(char) >= 127 for char in url)
        or "\\" in url or "#" in url
    ):
        raise WebApiReplayError("invalid replay URL")
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise WebApiReplayError("invalid replay URL") from None
    if (
        parsed.scheme not in {"http", "https", "ws", "wss"} or not host
        or parsed.username is not None or parsed.password is not None
    ):
        raise WebApiReplayError("unsupported replay URL")
    if "%" in host or host != host.lower() or host.endswith("."):
        raise WebApiReplayError("destination host must be canonical")
    # Reuse the existing strict host/port grammar, without wildcard destinations.
    if port is not None and not 1 <= port <= 65535:
        raise WebApiReplayError("invalid destination port")
    authority = f"[{host}]" if ":" in host else host
    try:
        DestinationGuard([f"{authority}:{port or (443 if parsed.scheme in {'https', 'wss'} else 80)}"])
    except Exception:
        raise WebApiReplayError("invalid destination host") from None
    port = port or (443 if parsed.scheme in {"https", "wss"} else 80)
    if not 1 <= port <= 65535 or parsed.netloc.endswith(":"):
        raise WebApiReplayError("invalid destination port")
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return parsed.scheme, host, port, target


def _origin(url: str) -> str:
    scheme, host, port, _target = _address(url)
    return f"{scheme}://{'[' + host + ']' if ':' in host else host}:{port}"


def _headers(value: Any, *, credentials: bool = False) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > 100:
        raise WebApiReplayError("invalid request headers")
    result: dict[str, str] = {}
    seen: set[str] = set()
    for key, item in value.items():
        if type(key) is not str or not _HEADER.fullmatch(key):
            raise WebApiReplayError("invalid request header name")
        _text(item, "request header", maximum=16384)
        lower = key.lower()
        if (
            lower in seen or lower in _TRANSPORT_HEADERS or lower.startswith("sec-websocket-")
            or any(ord(char) < 32 or ord(char) == 127 for char in item)
            or (not credentials and SENSITIVE_FIELD_PATTERNS.search(key))
        ):
            raise WebApiReplayError("credential or transport-controlled request header")
        try:
            item.encode("latin-1")
        except UnicodeError:
            raise WebApiReplayError("request header is not HTTP encodable") from None
        seen.add(lower)
        result[key] = item
    return result


def _graphql_query(query: Any) -> str:
    query = _text(query, "GraphQL query", maximum=1048576)
    if not query.strip():
        raise WebApiReplayError("GraphQL query is required")
    # Remove comments and quoted strings before classifying operation tokens.
    # Fail closed on malformed/unterminated quoted text rather than hiding tokens.
    scrubbed = []
    index = 0
    while index < len(query):
        char = query[index]
        if char == "#":
            end = query.find("\n", index)
            index = len(query) if end < 0 else end
        elif query.startswith('"""', index):
            end = query.find('"""', index + 3)
            if end < 0:
                raise WebApiReplayError("invalid GraphQL string")
            index = end + 3
        elif char == '"':
            index += 1
            while index < len(query) and query[index] != '"':
                index += 2 if query[index] == "\\" else 1
            if index >= len(query):
                raise WebApiReplayError("invalid GraphQL string")
            index += 1
        else:
            scrubbed.append(char)
            index += 1
    if "subscription" in re.findall(r"[_A-Za-z][_0-9A-Za-z]*", "".join(scrubbed)):
        raise WebApiReplayError("GraphQL subscriptions are unsupported")
    return query


def _wire_request(value: Mapping[str, Any]) -> ReplayRequest:
    request = value["request"]
    url, body = request["url"], request["body"]
    headers = dict(request["headers"])
    if request["protocol"] == "graphql":
        payload = {"query": request["graphql_query"], "variables": request["graphql_variables"]}
        if request["method"] == "GET":
            parsed = urlsplit(url)
            query = urlencode({"query": payload["query"], "variables": _json(payload["variables"])})
            url = urlunsplit(parsed._replace(query="&".join(filter(None, (parsed.query, query)))))
        else:
            body = _json(payload)
            if any(key.lower() == "content-type" and item.lower() != "application/json" for key, item in headers.items()):
                raise WebApiReplayError("GraphQL POST requires application/json")
            headers = {key: item for key, item in headers.items() if key.lower() != "content-type"}
            headers["Content-Type"] = "application/json"
    return ReplayRequest(
        request_id=request["request_id"], endpoint_id=request["request_id"], method=request["method"], url=url,
        headers=headers, body=body, protocol=request["protocol"], session_id=value["session_id"], role_id=value["role_id"],
        websocket_messages=list(request["websocket_messages"]),
    )


def _validate(value: Mapping[str, Any]) -> None:
    _closed(value, frozenset({"schema_version", "session_id", "role_id", "request_digest", "request",
                              "credential_references", "destination_policy", "budgets"}), "envelope")
    if value["schema_version"] != WEB_API_REPLAY_VERSION:
        raise WebApiReplayError("unsupported replay envelope version")
    _identifier(value["session_id"], "session")
    _identifier(value["role_id"], "role")
    request = _closed(value["request"], _REQUEST_FIELDS, "request")
    _identifier(request["request_id"], "request")
    if request["protocol"] not in {"http", "graphql", "websocket"} or request["method"] not in _METHODS:
        raise WebApiReplayError("unsupported protocol or method")
    _headers(request["headers"])
    if request["body"] is not None:
        _text(request["body"], "request body", maximum=1048576)
    if not isinstance(request["graphql_variables"], Mapping):
        raise WebApiReplayError("GraphQL variables must be an object")
    if request["protocol"] == "graphql":
        if request["method"] not in {"GET", "POST"} or request["body"] is not None:
            raise WebApiReplayError("GraphQL permits only GET/POST with structured query and variables")
        _graphql_query(request["graphql_query"])
        _json(request["graphql_variables"])
        if any(name in {"query", "variables", "operationName", "extensions"}
               for name, _item in parse_qsl(urlsplit(request["url"]).query, keep_blank_values=True)):
            raise WebApiReplayError("GraphQL URL cannot override structured operation fields")
    elif request["graphql_query"] is not None or request["graphql_variables"]:
        raise WebApiReplayError("GraphQL fields require the GraphQL protocol")
    if not isinstance(request["websocket_messages"], (list, tuple)):
        raise WebApiReplayError("WebSocket messages must be text")
    if request["protocol"] != "websocket" and request["websocket_messages"]:
        raise WebApiReplayError("WebSocket messages require the WebSocket protocol")
    refs = value["credential_references"]
    if not isinstance(refs, (list, tuple)) or len(refs) > 20:
        raise WebApiReplayError("invalid scoped credential references")
    reference_names, header_names = set(), {key.lower() for key in request["headers"]}
    for ref in refs:
        _closed(ref, {"reference", "header"}, "credential reference")
        _identifier(ref["reference"], "credential reference")
        name = ref["header"]
        if type(name) is not str or not _HEADER.fullmatch(name):
            raise WebApiReplayError("invalid credential header")
        lower = name.lower()
        if (
            lower in header_names or lower in _TRANSPORT_HEADERS or lower.startswith("sec-websocket-")
            or ref["reference"] in reference_names
        ):
            raise WebApiReplayError("duplicate or transport-controlled credential reference")
        reference_names.add(ref["reference"])
        header_names.add(lower)
    _sha(value["request_digest"], "request")
    if value["request_digest"] != digest({key: value[key] for key in (
        "session_id", "role_id", "request", "credential_references",
    )}, max_bytes=2097152):
        raise WebApiReplayError("request digest does not match replay content")
    budget = _closed(value["budgets"], set(_BUDGET_BOUNDS) | {"timeout_seconds"}, "budget")
    for key, (low, high) in _BUDGET_BOUNDS.items():
        if type(budget[key]) is not int or not low <= budget[key] <= high:
            raise WebApiReplayError(f"invalid {key} budget")
    timeout = budget["timeout_seconds"]
    if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise WebApiReplayError("invalid timeout budget")
    if budget["max_output_bytes"] < budget["max_response_body_bytes"]:
        raise WebApiReplayError("output budget cannot be smaller than response body budget")
    policy = _closed(value["destination_policy"], {"transport", "origin", "request_targets"}, "destination policy")
    scheme, host, _port, _target = _address(request["url"])
    if policy["origin"] != _origin(policy["origin"]) or policy["origin"] != _origin(request["url"]):
        raise WebApiReplayError("request origin differs from exact approved origin")
    if _address(policy["origin"])[3] != "/":
        raise WebApiReplayError("origin must not include a request target")
    if policy["transport"] == "production":
        if scheme not in {"https", "wss"}:
            raise WebApiReplayError("production transport requires TLS")
    elif policy["transport"] == "laboratory":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise WebApiReplayError("laboratory transport requires an explicit loopback IP")
    else:
        raise WebApiReplayError("unknown transport policy")
    targets = policy["request_targets"]
    if not isinstance(targets, (list, tuple)) or not targets or len(targets) > 11 or len(set(targets)) != len(targets):
        raise WebApiReplayError("invalid exact request targets")
    for target in targets:
        if (
            type(target) is not str or not target.startswith("/") or target.startswith("//")
            or _address(policy["origin"] + target)[3] != target
        ):
            raise WebApiReplayError("invalid exact request target")
    wire = _wire_request(value)
    if _address(wire.url)[3] not in targets:
        raise WebApiReplayError("request target is not approved")
    if (request["protocol"] == "websocket") != (scheme in {"ws", "wss"}):
        raise WebApiReplayError("protocol and URL scheme differ")
    try:
        _validate_wire_request(wire)
        if request["protocol"] == "websocket":
            websocket.validate_request(wire, _websocket_budget(budget))
    except Exception as error:
        raise WebApiReplayError("unsupported or over-budget wire request") from error
    # GET GraphQL query/variables consume the same body budget as POST, before URL encoding.
    body_bytes = len((wire.body or "").encode("utf-8"))
    if request["protocol"] == "graphql":
        body_bytes = len(_json({"query": request["graphql_query"], "variables": request["graphql_variables"]}).encode())
    if body_bytes > budget["max_request_body_bytes"]:
        raise WebApiReplayError("request body byte budget exceeded")
    if _request_header_bytes(wire) > budget["max_request_header_bytes"]:
        raise WebApiReplayError("request header byte budget exceeded")


def _websocket_budget(value: Mapping[str, Any]) -> ReplayBudget:
    return ReplayBudget(
        max_requests=1, timeout_seconds=value["timeout_seconds"], max_redirect_hops=0,
        max_websocket_frames=value["max_websocket_frames"],
        max_websocket_message_bytes=value["max_websocket_message_bytes"], max_websocket_bytes=value["max_websocket_bytes"],
    )


def _request_header_bytes(request: ReplayRequest) -> int:
    if request.protocol == "websocket":
        return len(websocket.handshake_request(request, "A" * 24))
    _scheme, host, port, target = _address(request.url)
    return len((f"{request.method} {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n"
                f"Content-Length: {len((request.body or '').encode('utf-8'))}\r\n"
                + "".join(f"{key}: {item}\r\n" for key, item in request.headers.items()) + "\r\n").encode("latin-1"))


@dataclass(frozen=True)
class WebApiReplayEnvelope:
    """Owned immutable JSON snapshot of one exact approved replay request."""

    _canonical_json: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WebApiReplayEnvelope:
        try:
            canonical = _json(value)
            if len(canonical.encode()) > 2097152:
                raise WebApiReplayError("replay envelope byte limit exceeded")
            owned = json.loads(canonical)
            _validate(owned)
        except WebApiReplayError:
            raise
        except (TypeError, ValueError, KeyError, RecursionError, OverflowError):
            raise WebApiReplayError("invalid replay envelope") from None
        return cls(canonical)

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical_json)

    @property
    def request(self) -> dict[str, Any]:
        return self.to_dict()["request"]

    @property
    def digest(self) -> str:
        return digest(self.to_dict(), max_bytes=2097152)


def validate_web_api_operation(operation: Mapping[str, Any]) -> WebApiReplayEnvelope:
    """Validate the registered operation without accepting legacy replay metadata."""
    if (
        operation.get("tool") != WEB_API_REPLAY_TOOL or operation.get("tool_version") != WEB_API_REPLAY_VERSION
        or operation.get("action") != "replay"
    ):
        raise WebApiReplayError("unregistered or legacy Web API executable operation")
    arguments = _closed(operation.get("arguments"), {"envelope"}, "operation arguments")
    envelope = WebApiReplayEnvelope.from_dict(arguments["envelope"])
    egress = _closed(operation.get("egress_policy"), {"web_api_replay"}, "operation egress policy")
    if egress["web_api_replay"] != envelope.to_dict()["destination_policy"]:
        raise WebApiReplayError("operation egress policy differs from approved envelope")
    return envelope


class _ResponseReader:
    """Bound every peer metadata line, including chunk-size lines and trailers."""

    def __init__(self, sock: socket.socket, maximum: int, deadline: _ReplayDeadline) -> None:
        self.stream = sock.makefile("rb")
        self.sock, self.maximum, self.deadline = sock, maximum, deadline
        self.metadata_bytes = 0

    def readline(self, limit: int = -1) -> bytes:
        self.sock.settimeout(self.deadline.remaining())
        remaining = self.maximum - self.metadata_bytes + 1
        line = self.stream.readline(min(limit, remaining) if limit >= 0 else remaining)
        self.metadata_bytes += len(line)
        if self.metadata_bytes > self.maximum:
            raise WebApiReplayError("response metadata byte budget exceeded")
        return line

    def read(self, amount: int = -1) -> bytes:
        self.sock.settimeout(self.deadline.remaining())
        return self.stream.read(amount)

    def readinto(self, buffer: bytearray) -> int:
        self.sock.settimeout(self.deadline.remaining())
        return self.stream.readinto(buffer)

    def read1(self, amount: int = -1) -> bytes:
        self.sock.settimeout(self.deadline.remaining())
        return self.stream.read1(amount)

    def flush(self) -> None:
        self.stream.flush()

    def close(self) -> None:
        self.stream.close()


class _ResponseSocket:
    def __init__(self, reader: _ResponseReader) -> None:
        self.reader = reader

    def makefile(self, mode: str) -> _ResponseReader:
        if mode != "rb":
            raise WebApiReplayError("unsupported response parser stream")
        return self.reader


class _WebSocketSocket:
    """Apply the approved HTTP header cap to the fixed WebSocket handshake."""

    def __init__(self, sock: socket.socket, maximum: int) -> None:
        self.sock, self.maximum = sock, maximum
        self.handshake = bytearray()
        self.handshake_complete = False

    def settimeout(self, timeout: float) -> None:
        self.sock.settimeout(timeout)

    def sendall(self, content: bytes) -> None:
        self.sock.sendall(content)

    def recv(self, amount: int) -> bytes:
        content = self.sock.recv(amount)
        if not self.handshake_complete:
            self.handshake.extend(content)
            if len(self.handshake) > self.maximum:
                raise websocket.WebSocketBudgetError("response handshake byte budget exceeded")
            self.handshake_complete = self.handshake.endswith(b"\r\n\r\n")
        return content


class WebApiReplayMediator:
    """One-use parent-side mediator, bound to a consumed approval and exact plan.

    The supervisor constructs this only after verifying its signed approval
    consumption receipt. The adapter can submit only its approved envelope over
    the typed broker; it cannot select a socket, resolver or credential value.
    """

    def __init__(
        self, *, scope_guard: ScopeGuard, envelope: WebApiReplayEnvelope,
        plan_digest: str, approval_digest: str,
        credential_resolver: Callable[[str, str, str], str] | None = None,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.envelope = WebApiReplayEnvelope.from_dict(envelope.to_dict())
        self.plan_digest, self.approval_digest = _sha(plan_digest, "plan"), _sha(approval_digest, "approval")
        self.scope_guard, self.credential_resolver = scope_guard, credential_resolver
        self.tls_context = tls_context
        self._consumed = False
        self._lock = threading.Lock()

    def dispatch(
        self, value: Mapping[str, Any], *, plan_digest: str, approval_digest: str,
        cancellation_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        candidate = WebApiReplayEnvelope.from_dict(value)
        if (
            plan_digest != self.plan_digest or approval_digest != self.approval_digest
            or candidate.digest != self.envelope.digest
        ):
            raise WebApiReplayError("replay request does not match immutable approval/plan binding")
        with self._lock:
            if self._consumed:
                raise WebApiReplayError("approved replay request is already consumed")
            self._consumed = True
        owned = candidate.to_dict()
        deadline = _ReplayDeadline(owned["budgets"]["timeout_seconds"], cancellation_event)
        done = threading.Event()
        outcome: list[dict[str, Any] | BaseException] = []

        def exchange() -> None:
            try:
                deadline.remaining()
                outcome.append(self._exchange(owned, deadline))
            except BaseException as error:
                outcome.append(error)
            finally:
                done.set()

        worker = threading.Thread(target=exchange, name="cops-web-api-mediator", daemon=True)
        worker.start()
        try:
            while not done.wait(min(0.02, deadline.remaining())):
                deadline.remaining()
            deadline.remaining()
        except BaseException:
            deadline.cancel()
            worker.join(timeout=0.2 if deadline.active_socket is not None else 0)
            raise
        worker.join()
        if isinstance(outcome[0], BaseException):
            if isinstance(outcome[0], WebApiReplayError):
                raise outcome[0] from None
            if isinstance(outcome[0], Exception):
                # Peer parser exceptions can contain raw status lines or bytes.
                raise WebApiReplayError("bounded Web API transport failed") from None
            raise outcome[0]
        return outcome[0]

    def _exchange(self, value: dict[str, Any], deadline: _ReplayDeadline) -> dict[str, Any]:
        if self.scope_guard is None or self.scope_guard.scope.egress_allowed is not True:
            raise WebApiReplayError("runtime Web API egress is disabled")
        budget, policy = value["budgets"], value["destination_policy"]
        request = _wire_request(value)
        self.scope_guard.check_destination(request.url)
        secrets = []
        for ref in value["credential_references"]:
            deadline.remaining()
            if self.credential_resolver is None:
                raise WebApiReplayError("scoped credential resolver is unavailable")
            try:
                secret = self.credential_resolver(ref["reference"], value["session_id"], value["role_id"])
            except Exception:
                raise WebApiReplayError("scoped credential resolution failed") from None
            deadline.remaining()
            _headers({ref["header"]: secret}, credentials=True)
            request.headers[ref["header"]] = secret
            secrets.append(secret)
        if _request_header_bytes(request) > budget["max_request_header_bytes"]:
            raise WebApiReplayError("resolved request headers exceed their byte budget")
        scheme, host, port, _target = _address(request.url)
        authority = f"[{host}]" if ":" in host else host
        transport = StandardHttpReplayer(
            DestinationGuard([f"{authority}:{port}"]), self.scope_guard, tls_context=self.tls_context,
        )
        if request.protocol == "websocket":
            sock = transport._connect(urlsplit(request.url), deadline)
            try:
                response = websocket.exchange(
                    _WebSocketSocket(sock, budget["max_response_header_bytes"]),
                    request, _websocket_budget(budget), deadline,
                )
                if not response.replay_success:
                    raise WebApiReplayError("WebSocket replay failed its bounded text contract")
                if sum(len(item.encode("utf-8")) for item in response.websocket_replies) > budget["max_response_body_bytes"]:
                    raise WebApiReplayError("WebSocket transcript body byte budget exceeded")
                result = response.to_dict()
            finally:
                sock.close()
            return self._output(result, budget, secrets)
        url = request.url
        for hop in range(budget["max_redirect_hops"] + 1):
            if _origin(url) != policy["origin"] or _address(url)[3] not in policy["request_targets"]:
                raise WebApiReplayError("unapproved replay origin or request target")
            self.scope_guard.check_destination(url)
            sock = transport._connect(urlsplit(url), deadline)
            try:
                target = _address(url)[3]
                body = (request.body or "").encode("utf-8")
                headers = dict(request.headers)
                headers["Host"] = authority + (f":{port}" if port != (443 if scheme == "https" else 80) else "")
                headers["Content-Length"] = str(len(body))
                headers["Connection"] = "close"
                encoded = (f"{request.method} {target} HTTP/1.1\r\n"
                           + "".join(f"{name}: {item}\r\n" for name, item in headers.items()) + "\r\n").encode("latin-1")
                if len(encoded) > budget["max_request_header_bytes"]:
                    raise WebApiReplayError("redirect request headers exceed their byte budget")
                sock.settimeout(deadline.remaining())
                sock.sendall(encoded + body)
                reader = _ResponseReader(sock, budget["max_response_header_bytes"], deadline)
                response = http.client.HTTPResponse(_ResponseSocket(reader), method=request.method)
                try:
                    response.begin()
                    if response.headers.defects or not 200 <= response.status <= 599:
                        raise WebApiReplayError("invalid response status or headers")
                    response_headers = response.getheaders()
                    self._response_headers(response_headers)
                    if response.status == 101:
                        raise WebApiReplayError("unrestricted protocol upgrades are forbidden")
                    if response.status in {301, 302, 303, 307, 308}:
                        locations = [item for name, item in response_headers if name.lower() == "location"]
                        if locations:
                            # Only preserving-method transitions can represent the exact approved request.
                            if response.status not in {307, 308} or hop == budget["max_redirect_hops"]:
                                raise WebApiReplayError("redirect exceeds the exact approved replay contract")
                            url = urljoin(url, locations[0])
                            continue
                    content = bytearray()
                    while len(content) <= budget["max_response_body_bytes"]:
                        deadline.remaining()
                        chunk = response.read1(min(65536, budget["max_response_body_bytes"] + 1 - len(content)))
                        if not chunk:
                            break
                        content.extend(chunk)
                    if len(content) > budget["max_response_body_bytes"]:
                        raise WebApiReplayError("response body byte budget exceeded")
                    deadline.remaining()
                    result = {"request_id": request.request_id, "status": response.status,
                              "headers": dict(response_headers), "body": content.decode("utf-8", errors="replace"),
                              "redirect_count": hop}
                    return self._output(result, budget, secrets)
                finally:
                    response.close()
                    reader.close()
            finally:
                sock.close()
        raise WebApiReplayError("redirect budget exceeded")

    @staticmethod
    def _response_headers(headers: list[tuple[str, str]]) -> None:
        names = []
        for name, value in headers:
            if not _HEADER.fullmatch(name) or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise WebApiReplayError("invalid response headers")
            names.append(name.lower())
        if len(names) != len(set(names)):
            raise WebApiReplayError("duplicate response headers are unsupported")
        values = {name.lower(): item for name, item in headers}
        if "transfer-encoding" in values and values["transfer-encoding"].lower() != "chunked":
            raise WebApiReplayError("unsupported response transfer encoding")
        if "transfer-encoding" in values and "content-length" in values:
            raise WebApiReplayError("ambiguous response length")
        if "content-length" in values and not re.fullmatch(r"[0-9]{1,20}", values["content-length"]):
            raise WebApiReplayError("invalid response length")
        if values.get("content-encoding", "identity").lower() != "identity":
            raise WebApiReplayError("compressed replay responses are unsupported")

    @staticmethod
    def _output(result: dict[str, Any], budget: Mapping[str, Any], secrets: list[str]) -> dict[str, Any]:
        # Do not export response credentials, cookies or reflected resolved values.
        result["headers"] = {
            name: item for name, item in result.get("headers", {}).items()
            if not SENSITIVE_FIELD_PATTERNS.search(name)
        }
        reflected = set(secrets)
        reflected.update(_json(secret)[1:-1] for secret in secrets)

        def redact(value: Any) -> Any:
            if isinstance(value, str):
                for secret in sorted(reflected, key=len, reverse=True):
                    if secret:
                        value = value.replace(secret, "[REDACTED]")
                return value
            if isinstance(value, dict):
                return {redact(key): redact(item) for key, item in value.items()}
            if isinstance(value, list):
                return [redact(item) for item in value]
            return value

        text = _json(redact(result))
        if len(text.encode()) > budget["max_output_bytes"]:
            raise WebApiReplayError("replay output byte budget exceeded")
        return json.loads(text)
