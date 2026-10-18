"""Bounded API request preview, offline replay, and approved live replay."""

from __future__ import annotations

import http.client
import ipaddress
import math
import re
import socket
import ssl
import threading
import time
from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest, utc_now
from cops.execution.control import ApprovalConsumptionReceipt, ApprovalControl
from cops.execution.scope_guard import ScopeGuard, ScopeViolationError

from .models import (
    ApiProtocol,
    ReplayBudget,
    ReplayRequest,
    ReplayResponse,
    ReplaySessionReport,
    SessionContext,
)
from .sanitization import SENSITIVE_FIELD_PATTERNS, authority, sanitize_reference


class DestinationViolationError(Exception):
    """A replay destination is outside its explicit destination allowlist."""


class ReplayBudgetExceededError(Exception):
    """An operational replay budget is invalid or exhausted."""


class ReplayAuthorizationError(Exception):
    """Live replay is missing or does not match an approved action plan."""


class DestinationGuard:
    """Match URL hosts against exact hosts, exact host:ports, or wildcard domains."""

    def __init__(self, allowed_destinations: list[str]) -> None:
        self.allowed_destinations = [item.strip().lower() for item in allowed_destinations if item.strip()]

    def is_destination_allowed(self, url: str) -> bool:
        try:
            parsed = _parse_destination(url)
        except (ValueError, TypeError):
            return False
        host = parsed.hostname.lower()
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme in {"https", "wss"} else 80)
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        for allowed in self.allowed_destinations:
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if host == suffix or host.endswith("." + suffix):
                    return True
            elif allowed == host or allowed == authority:
                return True
        return False

    def check_destination(self, url: str) -> None:
        if not self.is_destination_allowed(url):
            raise DestinationViolationError("destination is outside the authorized allowlist")


class Replayer(ABC):
    """Request replayer interface."""

    @abstractmethod
    def send(self, req: ReplayRequest, budget: ReplayBudget) -> ReplayResponse:
        """Send one request within the supplied budget."""


@dataclass(frozen=True)
class _WireRequest:
    """Owned request plus header provenance needed by redirect policy."""

    request: ReplayRequest
    credential_header_names: frozenset[str]


class OfflineSyntheticReplayer(Replayer):
    """Deterministic offline simulation used for safe previews and tests."""

    def __init__(
        self,
        mock_routes: dict[str, dict[str, Any]] | None = None,
        simulate_latency_ms: float = 2.0,
    ) -> None:
        self.mock_routes = mock_routes or {}
        self.simulate_latency_ms = simulate_latency_ms
        self.requests_sent: list[ReplayRequest] = []

    def send(self, req: ReplayRequest, budget: ReplayBudget) -> ReplayResponse:
        self.requests_sent.append(req)
        parsed = urlparse(req.url)
        route = self.mock_routes.get(f"{req.method.upper()} {parsed.path}") or self.mock_routes.get(parsed.path) or {}
        redirect_to = route.get("redirect_to")
        if redirect_to:
            hops = int(route.get("redirect_hops", 1))
            if hops > budget.max_redirect_hops:
                return ReplayResponse(
                    request_id=req.request_id,
                    status_code=302,
                    headers={"Location": str(redirect_to)},
                    body_excerpt="Redirect limit exceeded",
                    latency_ms=self.simulate_latency_ms,
                    redirect_count=hops,
                    final_url=str(redirect_to),
                    error_message="Maximum redirect hops exceeded",
                    replay_success=False,
                )
            return ReplayResponse(
                request_id=req.request_id,
                status_code=int(route.get("final_status", 200)),
                headers=dict(route.get("headers", {"Content-Type": "application/json"})),
                body_excerpt=str(route.get("body", '{"status":"ok","redirected":true}')),
                latency_ms=self.simulate_latency_ms,
                redirect_count=hops,
                final_url=str(redirect_to),
            )
        if req.protocol == ApiProtocol.GRAPHQL.value or "graphql" in parsed.path.lower():
            query = req.graphql_query or req.body or ""
            body = route.get("body")
            if body is None and ("IntrospectionQuery" in query or "__schema" in query):
                body = '{"data":{"__schema":{"types":[{"name":"User"},{"name":"Query"}]}}}'
            return ReplayResponse(
                request_id=req.request_id,
                status_code=int(route.get("status", 200)),
                headers=dict(route.get("headers", {"Content-Type": "application/json"})),
                body_excerpt=str(body or '{"data":{"result":"success"}}'),
                latency_ms=self.simulate_latency_ms,
                final_url=req.url,
                replay_success=not route.get("error"),
                error_message=route.get("error"),
            )
        if req.protocol == ApiProtocol.WEBSOCKET.value:
            messages = (req.websocket_messages or ["ping"])[: budget.max_websocket_frames]
            return ReplayResponse(
                request_id=req.request_id,
                status_code=101,
                headers={"Upgrade": "websocket", "Connection": "Upgrade"},
                body_excerpt="WebSocket connection established and frames exchanged",
                latency_ms=self.simulate_latency_ms,
                websocket_replies=[f"echo:{message}" for message in messages],
                final_url=req.url,
            )
        status = int(route.get("status", 200))
        return ReplayResponse(
            request_id=req.request_id,
            status_code=status,
            headers=dict(route.get("headers", {"Content-Type": "application/json"})),
            body_excerpt=str(route.get("body", '{"message":"Synthetic response","success":true}')),
            latency_ms=self.simulate_latency_ms,
            final_url=req.url,
            error_message=route.get("error"),
            replay_success=not route.get("error"),
        )


def _parse_destination(url: str):
    # urlparse discards some controls; reject them before parsing or signing.
    if not isinstance(url, str) or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("invalid destination characters")
    if "\\" in url:
        raise ValueError("ambiguous destination separator")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        raise ValueError("unsupported destination")
    if parsed.username is not None or parsed.password is not None or "%" in parsed.hostname:
        raise ValueError("userinfo and encoded or scoped hosts are unsupported")
    if parsed.netloc.endswith(":") or parsed.port == 0:
        raise ValueError("invalid destination port")
    return parsed


def _origin(url: str) -> tuple[str, str, int]:
    parsed = _parse_destination(url)
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _validate_wire_request(req: ReplayRequest) -> None:
    if req.protocol not in {ApiProtocol.HTTP.value, ApiProtocol.GRAPHQL.value}:
        raise ReplayAuthorizationError("live replay supports HTTP and GraphQL only")
    if req.method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ReplayAuthorizationError("unsupported live replay method")
    if req.body is not None and not isinstance(req.body, str):
        raise ReplayAuthorizationError("request body must be UTF-8 text")
    seen = set()
    for name, value in req.headers.items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name) or not isinstance(value, str):
            raise ReplayAuthorizationError("invalid request header")
        key = name.lower()
        if key in seen or any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value):
            raise ReplayAuthorizationError("duplicate or invalid request header")
        seen.add(key)
        if key in {
            "host",
            "transfer-encoding",
            "proxy-authorization",
            "proxy-connection",
            "connection",
            "upgrade",
            "trailer",
            "expect",
        }:
            raise ReplayAuthorizationError("transport-controlled request header")
        if key == "content-length" and value != str(len((req.body or "").encode("utf-8"))):
            raise ReplayAuthorizationError("Content-Length does not match the request body")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as error:
            raise ReplayAuthorizationError("request header is not HTTP encodable") from error


class _ReplayDeadline:
    """Cancel socket work at an absolute deadline, including slow DNS and reads."""

    def __init__(self, seconds: float) -> None:
        self.expires = time.monotonic() + seconds
        self.cancelled = threading.Event()
        self.lock = threading.Lock()
        self.active_socket: socket.socket | None = None

    def remaining(self) -> float:
        remaining = self.expires - time.monotonic()
        if self.cancelled.is_set() or remaining <= 0:
            raise TimeoutError("replay deadline exceeded")
        return remaining

    def attach(self, sock: socket.socket) -> None:
        with self.lock:
            if self.cancelled.is_set():
                sock.close()
                raise TimeoutError("replay cancelled")
            self.active_socket = sock

    def cancel(self) -> None:
        with self.lock:
            self.cancelled.set()
            if self.active_socket is not None:
                try:
                    self.active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.active_socket.close()


class StandardHttpReplayer(Replayer):
    """Pinned-address HTTP transport with scope checks and an absolute deadline."""

    def __init__(
        self,
        destination_guard: DestinationGuard,
        scope_guard: ScopeGuard,
        *,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        if tls_context is not None:
            self._validate_tls_context(tls_context)
        self.destination_guard = destination_guard
        self.scope_guard = scope_guard
        self.tls_context = tls_context

    @staticmethod
    def _validate_tls_context(tls_context: ssl.SSLContext) -> None:
        if tls_context.verify_mode != ssl.CERT_REQUIRED or not tls_context.check_hostname:
            raise ReplayAuthorizationError("TLS context must enable certificate and hostname verification")

    def _exchange(
        self,
        req: ReplayRequest,
        budget: ReplayBudget,
        deadline: _ReplayDeadline,
        credential_header_names: frozenset[str],
    ) -> ReplayResponse:
        url = req.url
        if req.query_parameters:
            parsed = _parse_destination(url)
            query = urlencode(req.query_parameters)
            url = urlunparse(parsed._replace(query=f"{parsed.query}&{query}" if parsed.query else query))
        method, body, headers = req.method.upper(), req.body, dict(req.headers)
        for hops in range(budget.max_redirect_hops + 1):
            self.destination_guard.check_destination(url)
            parsed = _parse_destination(url)
            if parsed.scheme not in {"http", "https"}:
                raise DestinationViolationError("only HTTP and HTTPS replay are supported")
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            deadline.remaining()
            try:
                addresses = [str(ipaddress.ip_address(host))]
            except ValueError:
                addresses = self.scope_guard.resolver(host)
            # An expired resolver may finish later, but must never open a socket.
            deadline.remaining()
            self.scope_guard.check_resolved_destination(host, addresses)
            address = ipaddress.ip_address(addresses[0])
            sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
            connection = http.client.HTTPConnection(host, port, timeout=deadline.remaining())
            connection.auto_open = 0  # No reconnect and no implicit second DNS lookup.
            deadline.attach(sock)
            try:
                sock.settimeout(deadline.remaining())
                sock.connect((str(address), port))
                if parsed.scheme == "https":
                    tls_context = self.tls_context or ssl.create_default_context()
                    self._validate_tls_context(tls_context)
                    sock.settimeout(deadline.remaining())
                    sock = tls_context.wrap_socket(sock, server_hostname=host)
                    deadline.attach(sock)
                connection.sock = sock
                sock.settimeout(deadline.remaining())
                path = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
                connection.request(
                    method, path, body=body.encode("utf-8") if body is not None else None, headers=headers
                )
                sock.settimeout(deadline.remaining())
                response = connection.getresponse()
                with response:
                    response_headers = dict(response.headers.items())
                    location = response.headers.get("Location")
                    if response.status in {301, 302, 303, 307, 308} and location:
                        if hops == budget.max_redirect_hops:
                            raise DestinationViolationError("Maximum redirect hops exceeded")
                        target = urljoin(url, location)
                        self.destination_guard.check_destination(target)
                        old_origin, new_origin = _origin(url), _origin(target)
                        if old_origin[0] == "https" and new_origin[0] != "https":
                            raise DestinationViolationError("HTTPS redirect downgrade rejected")
                        if (
                            response.status == 303
                            and method != "HEAD"
                            or response.status in {301, 302}
                            and method == "POST"
                        ):
                            method, body = "GET", None
                            headers = {
                                key: value
                                for key, value in headers.items()
                                if key.lower() not in {"content-length", "content-type"}
                            }
                        retained_credentials = any(
                            name.lower() in credential_header_names or SENSITIVE_FIELD_PATTERNS.search(name)
                            for name in headers
                        )
                        if old_origin != new_origin:
                            if body is not None or retained_credentials:
                                raise DestinationViolationError(
                                    "cross-origin redirect with body or credentials rejected"
                                )
                            # Do not infer that an unfamiliar caller header is non-credential.
                            # A bodyless cross-origin follow-up starts with no caller/session headers.
                            headers = {}
                        url = target
                        continue
                    chunks: list[bytes] = []
                    remaining_bytes = 2048
                    while remaining_bytes:
                        deadline.remaining()
                        chunk = response.read1(remaining_bytes)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining_bytes -= len(chunk)
                    deadline.remaining()
                    return ReplayResponse(
                        request_id=req.request_id,
                        status_code=response.status,
                        headers=response_headers,
                        body_excerpt=b"".join(chunks).decode("utf-8", errors="replace"),
                        redirect_count=hops,
                        final_url=url,
                        replay_success=True,
                    )
            finally:
                connection.close()
                sock.close()
        raise DestinationViolationError("Maximum redirect hops exceeded")

    def send(
        self,
        req: ReplayRequest,
        budget: ReplayBudget,
        *,
        credential_header_names: frozenset[str] | None = None,
    ) -> ReplayResponse:
        _validate_budget(budget)
        _validate_wire_request(req)
        self.destination_guard.check_destination(req.url)
        owned_credential_header_names = frozenset(name.lower() for name in credential_header_names or ())
        started = time.monotonic()
        deadline = _ReplayDeadline(budget.timeout_seconds)
        done = threading.Event()
        result: list[ReplayResponse | Exception] = []

        def exchange() -> None:
            try:
                result.append(self._exchange(req, budget, deadline, owned_credential_header_names))
            except Exception as error:
                result.append(error)
            finally:
                done.set()

        threading.Thread(target=exchange, name="cops-api-replay", daemon=True).start()
        if not done.wait(max(0, deadline.expires - time.monotonic())):
            deadline.cancel()
            outcome: ReplayResponse | Exception = TimeoutError("replay deadline exceeded")
        else:
            outcome = result[0]
        if isinstance(outcome, (DestinationViolationError, ScopeViolationError)):
            raise outcome
        if isinstance(outcome, Exception):
            if not isinstance(outcome, (OSError, http.client.HTTPException, UnicodeError)):
                raise outcome
            outcome = ReplayResponse(
                request_id=req.request_id,
                status_code=0,
                final_url=req.url,
                error_message=type(outcome).__name__,
                replay_success=False,
            )
        outcome.latency_ms = (time.monotonic() - started) * 1000
        return outcome


def _sanitize_request(req: ReplayRequest) -> ReplayRequest:
    return ReplayRequest.from_dict(req.to_dict())


def _sanitize_response(response: ReplayResponse) -> ReplayResponse:
    return ReplayResponse.from_dict(response.to_dict())


def _validate_budget(budget: ReplayBudget) -> None:
    for name, low, high in (
        ("max_requests", 1, 1000),
        ("max_redirect_hops", 0, 10),
        ("max_websocket_frames", 0, 10000),
    ):
        value = getattr(budget, name)
        if type(value) is not int or not low <= value <= high:
            raise ReplayBudgetExceededError(f"{name} must be an integer between {low} and {high}")
    for name in ("timeout_seconds", "rate_limit_rps"):
        value = getattr(budget, name)
        if type(value) not in {int, float} or not math.isfinite(value):
            raise ReplayBudgetExceededError(f"{name} must be a finite number")
    if not 0 < budget.timeout_seconds <= 86400:
        raise ReplayBudgetExceededError("timeout_seconds must be greater than zero and at most 86400")
    if budget.rate_limit_rps != 0 and not 1 / 86400 <= budget.rate_limit_rps <= 1000000:
        raise ReplayBudgetExceededError("rate_limit_rps must be zero or between 1/86400 and 1000000")


def _report(
    *,
    requests: list[ReplayRequest],
    responses: list[ReplayResponse],
    allowed_destinations: list[str],
    budget: ReplayBudget,
    session_id: str | None,
    violations: int,
) -> ReplaySessionReport:
    targets = sorted({authority(item.url) for item in requests if urlparse(item.url).netloc})
    identifier = (
        session_id
        or f"rep-sess-{digest({'destinations': sorted(allowed_destinations), 'requests': [item.request_id for item in requests]})[:12]}"
    )
    return ReplaySessionReport(
        session_id=identifier,
        target_hosts=targets,
        allowed_destinations=list(allowed_destinations),
        budget=budget,
        requests=[_sanitize_request(item) for item in requests],
        responses=[_sanitize_response(item) for item in responses],
        total_dispatched=len(responses),
        total_successful=sum(item.replay_success for item in responses),
        total_failed=sum(not item.replay_success for item in responses),
        destination_violations=violations,
    )


def preview_replay_session(
    requests: list[ReplayRequest],
    allowed_destinations: list[str],
    budget: ReplayBudget | None = None,
    session_id: str | None = None,
) -> ReplaySessionReport:
    """Create a redacted, side-effect-free preview without dispatching requests."""
    active_budget = budget or ReplayBudget()
    _validate_budget(active_budget)
    if len(requests) > active_budget.max_requests:
        raise ReplayBudgetExceededError("request count exceeds max_requests")
    guard = DestinationGuard(allowed_destinations)
    for request in requests:
        guard.check_destination(request.url)
    return _report(
        requests=requests,
        responses=[],
        allowed_destinations=allowed_destinations,
        budget=active_budget,
        session_id=session_id,
        violations=0,
    )


def _live_request(req: ReplayRequest, sessions: dict[str, SessionContext]) -> _WireRequest:
    if req.session_id is None:
        credential_header_names = frozenset(
            name.lower() for name in req.headers if SENSITIVE_FIELD_PATTERNS.search(name)
        )
        return _WireRequest(request=req, credential_header_names=credential_header_names)
    session = sessions.get(req.session_id)
    if session is None or session.is_isolated is not True:
        raise ReplayAuthorizationError("request refers to an unknown or unisolated session")
    if req.role_id is not None and req.role_id != session.role_id:
        raise ReplayAuthorizationError("request role does not match its isolated session")
    headers = dict(session.headers)
    session_header_names = {name.lower() for name in headers}
    declared_credential_header_names = {name.lower() for name in headers if SENSITIVE_FIELD_PATTERNS.search(name)}
    if session.auth_mechanism.location.lower() == "header" and session.auth_mechanism.token_name:
        declared_credential_header_names.add(session.auth_mechanism.token_name.lower())
    credential_overrides = [
        name
        for name in req.headers
        if name.lower() in session_header_names and name.lower() in declared_credential_header_names
    ]
    if credential_overrides:
        raise ReplayAuthorizationError("request credentials cannot override isolated session credentials")
    request_cookie = next((value for key, value in req.headers.items() if key.lower() == "cookie"), None)
    if request_cookie is not None and session.cookies:
        raise ReplayAuthorizationError("request cookie cannot override isolated session cookies")
    if session.cookies:
        if any(
            not isinstance(key, str)
            or not _HEADER_NAME.fullmatch(key)
            or not isinstance(value, str)
            or any(char in value for char in ";\r\n")
            for key, value in session.cookies.items()
        ):
            raise ReplayAuthorizationError("invalid isolated session cookie")
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in sorted(session.cookies.items()))
    headers.update(req.headers)
    credential_header_names = set(session_header_names)
    if session.cookies:
        credential_header_names.add("cookie")
    credential_header_names.update(declared_credential_header_names)
    credential_header_names.update(name.lower() for name in headers if SENSITIVE_FIELD_PATTERNS.search(name))
    return _WireRequest(
        request=replace(req, headers=headers, role_id=req.role_id or session.role_id),
        credential_header_names=frozenset(credential_header_names),
    )


def _wire_requests(requests: list[ReplayRequest], sessions: list[SessionContext]) -> list[_WireRequest]:
    identifiers = [request.request_id for request in requests]
    if len(set(identifiers)) != len(identifiers):
        raise ReplayAuthorizationError("request identifiers must be unique")
    session_map = {session.session_id: session for session in sessions}
    if len(session_map) != len(sessions):
        raise ReplayAuthorizationError("session identifiers must be unique")
    wire = [_live_request(request, session_map) for request in requests]
    for item in wire:
        _validate_wire_request(item.request)
    return wire


def _plan_parts(
    wire_requests: list[_WireRequest],
    source_requests: list[ReplayRequest],
    sessions: list[SessionContext],
    budget: ReplayBudget,
    allowed_destinations: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if not wire_requests or len(wire_requests) != len(source_requests):
        raise ReplayAuthorizationError("live replay requires at least one request")
    sessions_digest = digest([asdict(session) for session in sessions])
    operations = [
        {
            "step_id": wire_request.request.request_id,
            "tool": "cops.web_api.standard-http-replayer",
            "tool_version": "2",
            "action": "replay_http_request",
            "arguments": {
                "request_digest": digest(asdict(wire_request.request)),
                "source_request_digest": digest(asdict(source_request)),
                "sessions_digest": sessions_digest,
                "budget_digest": digest(asdict(budget)),
                "destinations_digest": digest(allowed_destinations),
                "method": wire_request.request.method.upper(),
                "url": sanitize_reference(wire_request.request.url),
                "protocol": wire_request.request.protocol,
                "session_id": wire_request.request.session_id or "",
            },
            "timeout_seconds": max(1, math.ceil(budget.timeout_seconds)),
            "side_effects": ["network_connections"],
            "cleanup": {"strategy": "none", "resources": []},
        }
        for wire_request, source_request in zip(wire_requests, source_requests, strict=True)
    ]
    pacing_seconds = (len(wire_requests) - 1) / budget.rate_limit_rps if budget.rate_limit_rps > 0 else 0
    limits = {
        "max_duration_seconds": max(1, math.ceil(budget.timeout_seconds * len(wire_requests) + pacing_seconds)),
        "max_output_bytes": max(1, 2048 * len(wire_requests)),
        "egress_allowed": True,
    }
    batch = {"mode": "sequential", "max_operations": len(wire_requests), "fail_fast": True}
    return operations, limits, batch


def build_replay_action_plan(
    *,
    plan_id: str,
    engagement_id: str,
    scenario_id: str,
    specialist_id: str,
    requests: list[ReplayRequest],
    allowed_destinations: list[str],
    budget: ReplayBudget | None = None,
    credential_references: list[str] | None = None,
    sessions: list[SessionContext] | None = None,
    created_at: str | None = None,
) -> ActionPlan:
    """Build the exact immutable plan which an approval must authorize for live replay."""
    owned_requests = deepcopy(requests)
    owned_sessions = deepcopy(sessions or [])
    owned_destinations = deepcopy(allowed_destinations)
    active_budget = deepcopy(budget) if budget is not None else ReplayBudget()
    _validate_budget(active_budget)
    if not owned_destinations:
        raise ReplayAuthorizationError("live replay requires an explicit destination allowlist")
    if len(owned_requests) > active_budget.max_requests:
        raise ReplayBudgetExceededError("request count exceeds max_requests")
    identifiers = [request.request_id for request in owned_requests]
    if len(set(identifiers)) != len(identifiers):
        raise ReplayAuthorizationError("request identifiers must be unique")
    guard = DestinationGuard(owned_destinations)
    for request in owned_requests:
        guard.check_destination(request.url)
    wire = _wire_requests(owned_requests, owned_sessions)
    operations, limits, batch = _plan_parts(wire, owned_requests, owned_sessions, active_budget, owned_destinations)
    return ActionPlan.create(
        plan_id=plan_id,
        engagement_id=engagement_id,
        scenario_id=scenario_id,
        target=owned_destinations[0],
        specialist_id=specialist_id,
        operations=operations,
        limits=limits,
        credential_references=list(credential_references or []),
        created_at=created_at or utc_now(),
        batch=batch,
    )


def execute_replay_session(
    requests: list[ReplayRequest],
    allowed_destinations: list[str],
    budget: ReplayBudget | None = None,
    replayer: Replayer | None = None,
    session_id: str | None = None,
) -> ReplaySessionReport:
    """Run deterministic offline replay; network replay requires the approved entry point."""
    active_budget = budget or ReplayBudget()
    active_replayer = replayer or OfflineSyntheticReplayer()
    if not isinstance(active_replayer, OfflineSyntheticReplayer):
        raise ReplayAuthorizationError("live replay requires execute_authorized_replay_session")
    _validate_budget(active_budget)
    guard = DestinationGuard(allowed_destinations)
    selected = requests[: active_budget.max_requests]
    responses: list[ReplayResponse] = []
    violations = 0
    for request in selected:
        if not guard.is_destination_allowed(request.url):
            violations += 1
            responses.append(
                ReplayResponse(
                    request_id=request.request_id,
                    status_code=403,
                    body_excerpt="Target destination outside authorized allowlist",
                    final_url=request.url,
                    error_message="rejected by destination allowlist",
                    replay_success=False,
                )
            )
            continue
        responses.append(active_replayer.send(request, active_budget))
    return _report(
        requests=selected,
        responses=responses,
        allowed_destinations=allowed_destinations,
        budget=active_budget,
        session_id=session_id,
        violations=violations,
    )


def execute_authorized_replay_session(
    *,
    requests: list[ReplayRequest],
    sessions: list[SessionContext],
    allowed_destinations: list[str],
    scope_guard: ScopeGuard,
    budget: ReplayBudget,
    action_plan: ActionPlan,
    authorization_id: str,
    approval_control: ApprovalControl,
    worker_identity: str,
    session_id: str | None = None,
) -> ReplaySessionReport:
    """Consume one exact approval, then dispatch the corresponding bounded live replay."""
    owned_requests = deepcopy(requests)
    owned_sessions = deepcopy(sessions)
    owned_destinations = deepcopy(allowed_destinations)
    owned_budget = deepcopy(budget)
    _validate_budget(owned_budget)
    if not owned_destinations:
        raise ReplayAuthorizationError("live replay requires an explicit destination allowlist")
    if len(owned_requests) > owned_budget.max_requests:
        raise ReplayBudgetExceededError("request count exceeds max_requests")
    destination_guard = DestinationGuard(owned_destinations)
    wire_requests = _wire_requests(owned_requests, owned_sessions)
    for item in wire_requests:
        destination_guard.check_destination(item.request.url)
    expected_operations, expected_limits, expected_batch = _plan_parts(
        wire_requests, owned_requests, owned_sessions, owned_budget, owned_destinations
    )
    snapshot = action_plan.approved_snapshot()
    if (
        snapshot["target"] != owned_destinations[0]
        or snapshot["operations"] != expected_operations
        or snapshot["limits"] != expected_limits
        or snapshot["batch"] != expected_batch
    ):
        raise ReplayAuthorizationError("action plan does not match the requested replay")
    approval_control.assert_ready(worker_identity)
    receipt: ApprovalConsumptionReceipt | None = approval_control.consume_authorization(
        authorization_id, action_plan, worker_identity
    )
    try:
        receipt = approval_control.validate_receipt_provenance(receipt)
        replayer = StandardHttpReplayer(destination_guard, scope_guard)
        responses: list[ReplayResponse] = []
        delay = 1.0 / owned_budget.rate_limit_rps if owned_budget.rate_limit_rps > 0 else 0.0
        for index, item in enumerate(wire_requests):
            if index and delay:
                time.sleep(delay)
            response = replayer.send(
                item.request,
                owned_budget,
                credential_header_names=item.credential_header_names,
            )
            responses.append(response)
            if not response.replay_success:
                break
        return _report(
            requests=owned_requests,
            responses=responses,
            allowed_destinations=owned_destinations,
            budget=owned_budget,
            session_id=session_id,
            violations=0,
        )
    finally:
        if receipt is not None:
            approval_control.release_receipt_provenance(receipt)
