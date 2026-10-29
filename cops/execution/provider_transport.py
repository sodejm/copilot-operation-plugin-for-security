"""Explicitly registered gateway-owned HTTPS provider adapters.

These adapters never discover credentials, follow redirects, use proxies, or
retry a request. Raw provider content stays inside this boundary. Registration
does not establish provider IAM, retention, or live operational qualification.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import queue
import re
import socket
import ssl
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType
from urllib.parse import quote, urlsplit

from cops.evidence.canonical import canonical, decode_json

from .gateway_credentials import (
    LIVE_PROVIDER_TRANSPORT,
    AzureOpenAIResponseCredential,
    BedrockCredential,
    OpenAIResponseCredential,
    ProviderTransport,
    ResolvedCredential,
    VertexCredential,
)
from .gateway_dispatch import GatewayDispatchEndpoint, GatewayDispatchError, GatewayDispatchResponse

CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 5.0
TOTAL_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
TRANSPORT_VERSIONS = MappingProxyType(
    {
        "openai": "openai-responses/v1",
        "azure_openai": "azure-openai-responses/v1",
        "bedrock": "bedrock-converse/v1",
        "vertex": "vertex-generate-content/v1",
    }
)


class ProviderTransportError(GatewayDispatchError):
    """Sanitized failure; an uncertain send must never be retried automatically."""

    def __init__(self, *, send_state: str) -> None:
        self.send_state = send_state
        super().__init__("gateway provider transport failed")


class _DirectHTTPSConnection(http.client.HTTPSConnection):
    """Bound DNS, one address attempt, and TLS handshake without proxy discovery."""

    def connect(self) -> None:
        if getattr(self, "_connect_attempted", False):
            raise OSError("provider reconnect prohibited")
        self._connect_attempted = True
        deadline = min(time.monotonic() + CONNECT_TIMEOUT_SECONDS, getattr(self, "deadline", float("inf")))
        answers: queue.Queue = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                answers.put(socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM))
            except Exception:
                answers.put(None)

        threading.Thread(target=resolve, daemon=True).start()
        resolved = answers.get(timeout=max(0.001, deadline - time.monotonic()))
        if not resolved:
            raise OSError("provider connection unavailable")
        for resolved_family, resolved_kind, _, _, resolved_address in resolved:
            address = ipaddress.ip_address(resolved_address[0])
            if (
                resolved_family not in {socket.AF_INET, socket.AF_INET6}
                or resolved_kind != socket.SOCK_STREAM
                or resolved_address[1] != 443
                or not address.is_global
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
                or address.is_loopback
                or address.is_link_local
                or address.is_private
            ):
                raise OSError("provider address unavailable")
        family, kind, protocol, _, address = resolved[0]
        if time.monotonic() >= deadline:
            raise TimeoutError("provider connection deadline")
        self.sock = socket.socket(family, kind, protocol)
        self.sock.settimeout(max(0.001, deadline - time.monotonic()))
        self.sock.connect(address)
        if ipaddress.ip_address(self.sock.getpeername()[0]) != ipaddress.ip_address(address[0]):
            raise OSError("provider peer unavailable")
        if time.monotonic() >= deadline:
            raise TimeoutError("provider connection deadline")
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host, do_handshake_on_connect=False)
        self.sock.settimeout(max(0.001, deadline - time.monotonic()))
        self.sock.do_handshake()


def _target(endpoint: GatewayDispatchEndpoint, provider: str) -> tuple[str, str]:
    if not isinstance(endpoint, GatewayDispatchEndpoint) or LIVE_PROVIDER_TRANSPORT.get(endpoint.provider) != provider:
        raise ValueError("invalid provider scope")
    target = urlsplit(endpoint.request_target)
    if (
        target.scheme != "https"
        or not target.hostname
        or target.netloc != target.hostname
        or target.query
        or target.fragment
        or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in endpoint.request_target)
        or "%" in target.path
        or any(part in {"", ".", ".."} for part in target.path.split("/")[1:])
    ):
        raise ValueError("invalid provider target")
    paths = {
        "openai": "/v1/responses",
        "azure_openai": "/openai/v1/responses",
        "bedrock": f"/model/{endpoint.model}/converse",
        "vertex": (
            f"/v1/projects/{endpoint.account_or_project}/locations/{endpoint.region}"
            f"/publishers/google/models/{endpoint.model}:generateContent"
        ),
    }
    if target.path != paths[provider]:
        raise ValueError("invalid provider path")
    # Scope components cannot create additional path segments or header syntax.
    for part in (endpoint.model, endpoint.account_or_project, endpoint.region):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", part):
            raise ValueError("invalid provider scope")
    hosts = {
        "openai": "api.openai.com",
        "bedrock": f"bedrock-runtime.{endpoint.region}.amazonaws.com",
        "vertex": f"{endpoint.region}-aiplatform.googleapis.com",
    }
    if provider == "azure_openai":
        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.openai\.azure\.com",
            target.hostname,
        ):
            raise ValueError("invalid provider host")
    elif target.hostname != hosts[provider]:
        raise ValueError("invalid provider host")
    return target.hostname, target.path


def _headers(
    provider: str, endpoint: GatewayDispatchEndpoint, body: bytes, credential: ResolvedCredential
) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if provider == "openai" and type(credential) is OpenAIResponseCredential:
        headers["Authorization"] = f"Bearer {credential.api_key}"
    elif provider == "azure_openai" and type(credential) is AzureOpenAIResponseCredential:
        headers["api-key"] = credential.api_key
    elif provider == "vertex" and type(credential) is VertexCredential:
        headers["Authorization"] = f"Bearer {credential.access_token}"
    elif provider == "bedrock" and type(credential) is BedrockCredential:
        host, path = _target(endpoint, provider)
        moment = datetime.now(UTC)
        stamp, day = moment.strftime("%Y%m%dT%H%M%SZ"), moment.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        signed = {
            "content-type": "application/json",
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": stamp,
        }
        if credential.session_token is not None:
            signed["x-amz-security-token"] = credential.session_token
        names = ";".join(sorted(signed))
        canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in sorted(signed))
        request = "\n".join(("POST", quote(path, safe="/-_.~"), "", canonical_headers, names, payload_hash))
        scope = f"{day}/{endpoint.region}/bedrock/aws4_request"
        signing_string = f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{hashlib.sha256(request.encode()).hexdigest()}"
        key = ("AWS4" + credential.secret_access_key).encode()
        for component in (day, endpoint.region, "bedrock", "aws4_request"):
            key = hmac.new(key, component.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, signing_string.encode(), hashlib.sha256).hexdigest()
        headers.update(signed)
        headers["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={credential.access_key_id}/{scope}, "
            f"SignedHeaders={names}, Signature={signature}"
        )
    else:
        raise ValueError("provider credential mismatch")
    return headers


def _usage(source: dict, field: str, names: tuple[str, str, str]) -> dict:
    if field not in source:
        return {}
    value = source[field]
    if type(value) is not dict or any(type(value.get(name)) is not int for name in names):
        raise ValueError("invalid usage")
    counts = [value[name] for name in names]
    if any(count < 0 or count > 2**63 - 1 for count in counts) or counts[0] + counts[1] != counts[2]:
        raise ValueError("invalid usage")
    return {field: dict(zip(names, counts, strict=True))}


def _project(provider: str, raw: bytes) -> bytes:
    response = decode_json(raw, max_bytes=MAX_RESPONSE_BYTES, max_depth=16)
    if type(response) is not dict:
        raise ValueError("invalid provider response")
    if provider in {"openai", "azure_openai"}:
        status, output = response.get("status"), response.get("output")
        if status not in {"completed", "incomplete"} or type(output) is not list or len(output) > 32:
            raise ValueError("invalid provider response")
        # Only ordinary messages are permitted: no function, computer, search,
        # reasoning, or otherwise unknown output can cross this text-only route.
        for item in output:
            if type(item) is not dict or item.get("type") != "message":
                raise ValueError("unexpected provider output")
            content = item.get("content")
            if type(content) is not list or len(content) > 32:
                raise ValueError("unexpected provider output")
            for part in content:
                if type(part) is not dict or part.get("type") not in {"output_text", "refusal"}:
                    raise ValueError("unexpected provider output")
                key = "text" if part["type"] == "output_text" else "refusal"
                if type(part.get(key)) is not str:
                    raise ValueError("unexpected provider output")
        result = {"status": status, "output": []}
        if status == "incomplete":
            details = response.get("incomplete_details")
            if type(details) is not dict or details.get("reason") != "max_output_tokens":
                raise ValueError("invalid provider response")
            result["incomplete_details"] = {"reason": "max_output_tokens"}
        result.update(_usage(response, "usage", ("input_tokens", "output_tokens", "total_tokens")))
    elif provider == "bedrock":
        reason = response.get("stopReason")
        if reason not in {"end_turn", "max_tokens"}:
            raise ValueError("unexpected provider output")
        output = response.get("output")
        message = output.get("message") if type(output) is dict else None
        content = message.get("content") if type(message) is dict else None
        if (
            type(content) is not list
            or len(content) > 32
            or any(type(item) is not dict or set(item) != {"text"} or type(item["text"]) is not str for item in content)
        ):
            raise ValueError("unexpected provider output")
        result = {"stopReason": reason, "output": {"message": {"content": []}}}
        result.update(_usage(response, "usage", ("inputTokens", "outputTokens", "totalTokens")))
    else:
        candidates = response.get("candidates")
        if type(candidates) is not list or len(candidates) != 1 or type(candidates[0]) is not dict:
            raise ValueError("invalid provider response")
        candidate = candidates[0]
        reason = candidate.get("finishReason")
        content = candidate.get("content")
        parts = content.get("parts") if type(content) is dict else None
        if (
            reason not in {"STOP", "MAX_TOKENS"}
            or type(parts) is not list
            or len(parts) > 32
            or any(type(item) is not dict or set(item) != {"text"} or type(item["text"]) is not str for item in parts)
        ):
            raise ValueError("unexpected provider output")
        result = {"candidates": [{"finishReason": reason, "content": {"parts": []}}]}
        result.update(
            _usage(response, "usageMetadata", ("promptTokenCount", "candidatesTokenCount", "totalTokenCount"))
        )
    return canonical(result, max_bytes=MAX_RESPONSE_BYTES, max_depth=16)


def _read_response(
    response: http.client.HTTPResponse, connection: http.client.HTTPSConnection, max_response_bytes: int
) -> bytes:
    headers = response.getheaders()
    if len(headers) > 64 or sum(len(key) + len(value) for key, value in headers) > MAX_HEADER_BYTES:
        raise ValueError("provider header limit")
    values: dict[str, list[str]] = {}
    for key, value in headers:
        values.setdefault(key.lower(), []).append(value)
    media = values.get("content-type", [])
    if len(media) != 1 or not re.fullmatch(r"application/json(?:\s*;\s*charset=utf-8)?", media[0], re.IGNORECASE):
        raise ValueError("provider content type")
    if values.get("content-encoding", ["identity"]) != ["identity"]:
        raise ValueError("provider content encoding")
    lengths, transfers = values.get("content-length", []), values.get("transfer-encoding", [])
    if (lengths and transfers) or (transfers and transfers != ["chunked"]) or len(lengths) > 1:
        raise ValueError("provider framing")
    if lengths and (not re.fullmatch(r"[0-9]{1,10}", lengths[0]) or int(lengths[0]) > max_response_bytes):
        raise ValueError("provider response limit")
    chunks, size = [], 0
    while True:
        if connection.sock is not None:
            connection.sock.settimeout(READ_TIMEOUT_SECONDS)
        chunk = response.read(min(64 * 1024, max_response_bytes + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > max_response_bytes:
            raise ValueError("provider response limit")
    if lengths and size != int(lengths[0]):
        raise ValueError("provider truncated response")
    return b"".join(chunks)


class GatewayProviderTransport:
    """One fixed provider protocol with a bounded direct HTTPS exchange."""

    production_only = True

    def __init__(
        self,
        provider: str,
        *,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_elapsed_ms: int = int(TOTAL_TIMEOUT_SECONDS * 1000),
    ) -> None:
        if (
            provider not in TRANSPORT_VERSIONS
            or type(max_response_bytes) is not int
            or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
            or type(max_elapsed_ms) is not int
            or not 1 <= max_elapsed_ms <= int(TOTAL_TIMEOUT_SECONDS * 1000)
        ):
            raise GatewayDispatchError("gateway provider transport unavailable")
        self.provider = provider
        self.transport_version = TRANSPORT_VERSIONS[provider]
        self.max_response_bytes = max_response_bytes
        self.max_elapsed_ms = max_elapsed_ms

    def validate_endpoint(self, endpoint: GatewayDispatchEndpoint) -> None:
        """Validate the immutable provider target without resolving credentials.

        Production dispatchers call this during preflight, before consuming the
        one-use grant or resolving its scoped credential.  ``__call__`` repeats
        the same validation at the network transition so a preflight result can
        never authorize a later target mutation.
        """
        _target(endpoint, self.provider)

    def __call__(
        self, endpoint: GatewayDispatchEndpoint, body: bytes, credential: ResolvedCredential
    ) -> GatewayDispatchResponse:
        connection = None
        timer = None
        active_socket = None
        expired = threading.Event()
        sent = False
        try:
            host, path = _target(endpoint, self.provider)
            if type(body) is not bytes or not body or len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("provider request limit")
            headers = _headers(self.provider, endpoint, body, credential)
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = _DirectHTTPSConnection(host, timeout=READ_TIMEOUT_SECONDS, context=context)
            connection.deadline = time.monotonic() + self.max_elapsed_ms / 1000

            def cancel() -> None:
                expired.set()
                current_socket = active_socket if active_socket is not None else connection.sock
                if current_socket is not None:
                    try:
                        current_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    connection.close()

            timer = threading.Timer(self.max_elapsed_ms / 1000, cancel)
            timer.daemon = True
            timer.start()
            connection.connect()
            active_socket = connection.sock
            if expired.is_set():
                raise TimeoutError("provider deadline")
            connection.sock.settimeout(READ_TIMEOUT_SECONDS)
            # Set before request: even a failed write may have reached the peer.
            sent = True
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("provider status")
            raw = _read_response(response, connection, self.max_response_bytes)
            projected = _project(self.provider, raw)
            if len(projected) > self.max_response_bytes:
                raise ValueError("provider projected response limit")
            if expired.is_set():
                raise TimeoutError("provider deadline")
            return GatewayDispatchResponse(status_code=200, media_type="application/json", body=projected)
        except Exception:
            # Raise outside the exception handler so even __context__ cannot
            # retain provider payloads, credential errors, or network details.
            send_state = "uncertain" if sent else "not_sent"
        finally:
            if timer is not None:
                timer.cancel()
            if connection is not None:
                connection.close()
        raise ProviderTransportError(send_state=send_state)


def registered_provider_transports(
    *, max_response_bytes: int = MAX_RESPONSE_BYTES, max_elapsed_ms: int = int(TOTAL_TIMEOUT_SECONDS * 1000)
) -> Mapping[str, ProviderTransport]:
    """Return explicit adapters; callers still supply scoped credential resolution."""
    return MappingProxyType(
        {
            provider: GatewayProviderTransport(
                provider, max_response_bytes=max_response_bytes, max_elapsed_ms=max_elapsed_ms
            )
            for provider in TRANSPORT_VERSIONS
        }
    )
