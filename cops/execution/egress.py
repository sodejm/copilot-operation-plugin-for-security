"""Execution-time HTTPS mediation for network-isolated adapters.

Adapters receive an inherited Unix socket, not an Internet-capable socket.  The
parent-side mediator resolves, connects, authenticates, and releases only a
bounded HTTPS response for an exact authorized service identity.  A worker must
combine this channel with an operating-system network namespace that denies the
adapter direct AF_INET and AF_INET6 access.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import math
import multiprocessing
import socket
import ssl
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, fields
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from time import monotonic
from types import MappingProxyType
from typing import Protocol
from urllib.parse import SplitResult, quote, unquote, urljoin, urlsplit

from .scope_guard import METADATA_ADDRESSES, ScopeGuard, ScopeViolationError

BROKER_FD_ENV = "COPS_EGRESS_BROKER_FD"
BROKER_PROTOCOL = "cops.execution-egress/v1"


class EgressMediationError(RuntimeError):
    """Raised when an outbound request cannot be mediated safely."""


class EgressProtocolError(EgressMediationError):
    """Raised when an adapter submits an invalid broker request."""


class AuthenticatedResourceScopeError(EgressMediationError):
    """Raised when the authenticated remote identity is not exactly allowed."""


@dataclass(frozen=True)
class AuthenticatedServiceIdentity:
    """Exact authenticated provider and resource dimensions for a remote service."""

    provider: str
    service: str
    account: str
    tenant: str
    cluster: str
    namespace: str
    resource: str

    def __post_init__(self) -> None:
        for field_definition in fields(self):
            field_name = field_definition.name
            value = getattr(self, field_name)
            if (
                not isinstance(value, str)
                or not value
                or value.strip() != value
                or "*" in value
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
            ):
                raise ValueError(f"authenticated service identity {field_name} must be exact and non-empty")

    def as_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "service": self.service,
            "account": self.account,
            "tenant": self.tenant,
            "cluster": self.cluster,
            "namespace": self.namespace,
            "resource": self.resource,
        }


@dataclass(frozen=True)
class AuthenticatedServiceAllowlist:
    """Bind each exact authenticated identity to exact HTTP request targets."""

    request_targets: Mapping[AuthenticatedServiceIdentity, frozenset[str]]

    def __post_init__(self) -> None:
        if not isinstance(self.request_targets, Mapping) or not self.request_targets:
            raise ValueError("authenticated service allowlist cannot be empty")
        normalized: dict[AuthenticatedServiceIdentity, frozenset[str]] = {}
        for identity, targets in self.request_targets.items():
            if not isinstance(identity, AuthenticatedServiceIdentity):
                raise ValueError("authenticated service allowlist keys must be exact identities")
            if not isinstance(targets, frozenset) or not targets:
                raise ValueError("authenticated service allowlist targets must be non-empty frozen sets")
            checked_targets = frozenset(_validate_configured_request_target(target) for target in targets)
            normalized[identity] = checked_targets
        object.__setattr__(self, "request_targets", MappingProxyType(normalized))

    @property
    def identities(self) -> frozenset[AuthenticatedServiceIdentity]:
        return frozenset(self.request_targets)

    def require(self, identity: AuthenticatedServiceIdentity, *, request_target: str) -> None:
        targets = self.request_targets.get(identity)
        if targets is None:
            raise AuthenticatedResourceScopeError("authenticated service identity is outside the exact allowlist")
        if request_target not in targets:
            raise AuthenticatedResourceScopeError(
                "authenticated service request target is outside the exact identity allowlist"
            )


class ServiceIdentityVerifier(Protocol):
    """Derive a trusted service identity from an authenticated TLS peer."""

    def verify(
        self,
        *,
        hostname: str,
        peer_certificate_der: bytes,
        peer_certificate: Mapping[str, object],
    ) -> AuthenticatedServiceIdentity: ...


class CertificateURIIdentityVerifier:
    """Require one canonical workload URI SAN bound into the verified TLS peer.

    A normal public certificate authenticates a hostname, which can serve many
    accounts and resources.  This verifier requires the certificate presented on
    that already hostname-verified TLS session to also carry exactly one COPS URI
    SAN for the configured trust domain.  The URI encodes every resource scope
    dimension, so a shared hostname certificate without that binding fails closed.
    """

    _LABELS = ("provider", "service", "account", "tenant", "cluster", "namespace", "resource")

    def __init__(self, *, trust_domain: str) -> None:
        canonical = trust_domain.lower().rstrip(".")
        if not canonical or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-." for character in canonical):
            raise ValueError("certificate identity trust domain is invalid")
        self._trust_domain = canonical

    def verify(
        self,
        *,
        hostname: str,
        peer_certificate_der: bytes,
        peer_certificate: Mapping[str, object],
    ) -> AuthenticatedServiceIdentity:
        del hostname  # The TLS connector performs hostname verification.
        if not peer_certificate_der:
            raise AuthenticatedResourceScopeError("TLS peer did not present an authenticated certificate")
        subject_alt_names = peer_certificate.get("subjectAltName", ())
        if not isinstance(subject_alt_names, (tuple, list)):
            raise AuthenticatedResourceScopeError("TLS peer certificate subjectAltName is malformed")

        prefix = f"spiffe://{self._trust_domain}/cops/v1/"
        bindings = [
            value
            for item in subject_alt_names
            if isinstance(item, (tuple, list))
            and len(item) == 2
            and item[0] == "URI"
            and isinstance((value := item[1]), str)
            and value.startswith(prefix)
        ]
        if len(bindings) != 1:
            raise AuthenticatedResourceScopeError(
                "TLS peer must carry exactly one COPS resource identity URI for the trust domain"
            )

        path_parts = bindings[0][len(prefix) :].split("/")
        if len(path_parts) != len(self._LABELS) * 2 or tuple(path_parts[::2]) != self._LABELS:
            raise AuthenticatedResourceScopeError("TLS peer COPS resource identity URI is malformed")
        values: list[str] = []
        for encoded in path_parts[1::2]:
            try:
                value = unquote(encoded, errors="strict")
            except UnicodeDecodeError as err:
                raise AuthenticatedResourceScopeError(
                    "TLS peer COPS resource identity URI is not valid UTF-8"
                ) from err
            if (
                not value
                or value.strip() != value
                or "*" in value
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
                or quote(value, safe="") != encoded
            ):
                raise AuthenticatedResourceScopeError("TLS peer COPS resource identity URI is not canonical")
            values.append(value)
        return AuthenticatedServiceIdentity(**dict(zip(self._LABELS, values, strict=True)))


@dataclass(frozen=True)
class ResolvedEndpoint:
    family: int
    socktype: int
    proto: int
    sockaddr: tuple[object, ...]
    ip: str


@dataclass(frozen=True)
class MediatedResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    final_url: str
    identity: AuthenticatedServiceIdentity


@dataclass(frozen=True)
class EgressObservation:
    origin: str
    decision: str
    reason: str
    identity: AuthenticatedServiceIdentity | None = None


class OpenEgressConnection(Protocol):
    peer_ip: str
    peer_certificate_der: bytes
    peer_certificate: Mapping[str, object]

    def request(
        self,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        max_response_bytes: int,
        max_response_header_bytes: int,
        timeout_seconds: float,
    ) -> tuple[int, tuple[tuple[str, str], ...], bytes]: ...

    def close(self) -> None: ...


class EgressConnector(Protocol):
    def open(
        self,
        endpoint: ResolvedEndpoint,
        *,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> OpenEgressConnection: ...


class _MetadataBoundedReader:
    """Count every byte HTTPResponse consumes while parsing response metadata."""

    def __init__(self, stream: object, *, max_metadata_bytes: int) -> None:
        self._stream = stream
        self._max_metadata_bytes = max_metadata_bytes
        self._metadata_bytes = 0
        self._count_metadata = True

    def readline(self, limit: int = -1) -> bytes:
        read_limit = limit
        if self._count_metadata:
            remaining_plus_one = self._max_metadata_bytes - self._metadata_bytes + 1
            read_limit = remaining_plus_one if limit < 0 else min(limit, remaining_plus_one)
        line = self._stream.readline(read_limit)  # type: ignore[attr-defined]
        if self._count_metadata:
            self._metadata_bytes += len(line)
            if self._metadata_bytes > self._max_metadata_bytes:
                raise EgressMediationError("mediated HTTPS response metadata exceeded the configured byte limit")
        return line

    def finish_metadata(self) -> None:
        self._count_metadata = False

    def __getattr__(self, name: str) -> object:
        return getattr(self._stream, name)


class _MetadataBoundedSocket:
    """Present one metadata-counting file object to ``HTTPResponse``."""

    def __init__(self, tls_socket: ssl.SSLSocket, *, max_metadata_bytes: int) -> None:
        self._socket = tls_socket
        self._max_metadata_bytes = max_metadata_bytes
        self._reader: _MetadataBoundedReader | None = None

    def makefile(self, mode: str) -> _MetadataBoundedReader:
        if mode != "rb" or self._reader is not None:
            raise EgressMediationError("mediated HTTPS response parser requested an invalid stream")
        self._reader = _MetadataBoundedReader(
            self._socket.makefile(mode),
            max_metadata_bytes=self._max_metadata_bytes,
        )
        return self._reader

    def finish_metadata(self) -> None:
        if self._reader is None:
            raise EgressMediationError("mediated HTTPS response parser did not open a stream")
        self._reader.finish_metadata()


class _DirectTLSConnection:
    def __init__(self, tls_socket: ssl.SSLSocket, *, peer_ip: str) -> None:
        self._socket = tls_socket
        self.peer_ip = peer_ip
        self.peer_certificate_der = tls_socket.getpeercert(binary_form=True)
        if not self.peer_certificate_der:
            raise EgressMediationError("TLS peer did not present an authenticated certificate")
        certificate = tls_socket.getpeercert()
        if not isinstance(certificate, Mapping):
            raise EgressMediationError("TLS peer certificate metadata is unavailable")
        self.peer_certificate = certificate

    def request(
        self,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        max_response_bytes: int,
        max_response_header_bytes: int,
        timeout_seconds: float,
    ) -> tuple[int, tuple[tuple[str, str], ...], bytes]:
        self._socket.settimeout(timeout_seconds)
        request_lines = [f"{method} {target} HTTP/1.1"]
        request_lines.extend(f"{name}: {value}" for name, value in headers.items())
        request_lines.append("Connection: close")
        self._socket.sendall(("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii"))
        bounded_socket = _MetadataBoundedSocket(
            self._socket,
            max_metadata_bytes=max_response_header_bytes,
        )
        response = http.client.HTTPResponse(bounded_socket)
        try:
            response.begin()
        except EgressMediationError:
            raise
        except Exception as err:
            raise EgressMediationError("mediated HTTPS response metadata is invalid") from err
        bounded_socket.finish_metadata()
        body = response.read(max_response_bytes + 1)
        if len(body) > max_response_bytes:
            raise EgressMediationError("mediated HTTPS response exceeded the configured byte limit")
        return response.status, tuple(response.getheaders()), body

    def close(self) -> None:
        self._socket.close()


class DirectTLSConnector:
    """Connect directly to a prevalidated address without environment proxies."""

    def __init__(self, *, tls_context: ssl.SSLContext | None = None) -> None:
        context = tls_context or ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("TLS context must require certificate and hostname verification")
        self._tls_context = context

    def open(
        self,
        endpoint: ResolvedEndpoint,
        *,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> OpenEgressConnection:
        del port  # The validated port is already embedded in endpoint.sockaddr.
        raw_socket: socket.socket | None = None
        try:
            raw_socket = socket.socket(endpoint.family, endpoint.socktype, endpoint.proto)
            raw_socket.settimeout(timeout_seconds)
            raw_socket.connect(endpoint.sockaddr)
            peer_ip = _canonical_ip(raw_socket.getpeername()[0])
            tls_socket = self._tls_context.wrap_socket(raw_socket, server_hostname=hostname)
            return _DirectTLSConnection(tls_socket, peer_ip=peer_ip)
        except Exception as err:
            if raw_socket is not None:
                raw_socket.close()
            if isinstance(err, EgressMediationError):
                raise
            raise EgressMediationError("HTTPS connection to the validated endpoint failed") from err


Resolver = Callable[[str, int], tuple[ResolvedEndpoint, ...]]


class HTTPSExecutionMediator:
    """Perform structured HTTPS requests at the parent side of an isolated worker."""

    _FORBIDDEN_HEADERS = frozenset({
        "connection",
        "content-length",
        "expect",
        "forwarded",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    })
    _REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

    def __init__(
        self,
        *,
        scope_guard: ScopeGuard,
        identity_verifier: ServiceIdentityVerifier,
        identity_allowlist: AuthenticatedServiceAllowlist,
        resolver: Resolver | None = None,
        connector: EgressConnector | None = None,
        timeout_seconds: float = 15.0,
        max_response_bytes: int = 1_048_576,
        max_response_header_bytes: int = 65_536,
        max_redirects: int = 3,
    ) -> None:
        if not scope_guard.scope.egress_allowed:
            raise ValueError("execution egress mediator requires engagement egress_allowed=true")
        if (
            timeout_seconds <= 0
            or max_response_bytes <= 0
            or max_response_header_bytes <= 0
            or max_redirects < 0
        ):
            raise ValueError("execution egress mediator limits must be positive")
        self._scope_guard = scope_guard
        self._identity_verifier = identity_verifier
        self._identity_allowlist = identity_allowlist
        self._resolver = resolver or _default_resolver
        self._connector = connector or DirectTLSConnector()
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._max_response_header_bytes = max_response_header_bytes
        self._max_redirects = max_redirects
        self.observations: list[EgressObservation] = []

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        deadline: float | None = None,
    ) -> MediatedResponse:
        current_url = url
        operation_deadline = monotonic() + self._timeout_seconds
        if deadline is not None:
            operation_deadline = min(operation_deadline, deadline)
        try:
            _remaining_seconds(operation_deadline)
            if not isinstance(method, str):
                raise EgressProtocolError("egress broker request method must be a string")
            normalized_method = method.upper()
            if normalized_method not in {"GET", "HEAD"}:
                raise EgressProtocolError("egress broker permits only GET and HEAD; raw TCP and CONNECT are forbidden")
            checked_headers = self._validate_headers(headers if headers is not None else {})
            initial_origin: tuple[str, str, int] | None = None

            for redirect_count in range(self._max_redirects + 1):
                parsed = self._validate_url(current_url)
                origin = (parsed.scheme, parsed.hostname or "", parsed.port or 443)
                if initial_origin is None:
                    initial_origin = origin
                elif origin != initial_origin:
                    raise EgressProtocolError("mediated requests cannot redirect to a different origin")

                response = self._request_once(
                    normalized_method,
                    parsed,
                    checked_headers,
                    deadline=operation_deadline,
                )
                if response.status not in self._REDIRECT_STATUSES:
                    self.observations.append(
                        EgressObservation(
                            origin=_redacted_origin(current_url),
                            decision="allowed",
                            reason="authenticated_exact_scope",
                            identity=response.identity,
                        )
                    )
                    return response

                location = _required_single_header(response.headers, "location")
                if redirect_count == self._max_redirects:
                    raise EgressProtocolError("redirect limit exceeded")
                current_url = urljoin(current_url, location)
        except (EgressMediationError, ScopeViolationError) as err:
            self.observations.append(
                EgressObservation(
                    origin=_redacted_origin(current_url),
                    decision="blocked",
                    reason=type(err).__name__,
                )
            )
            raise

        raise AssertionError("redirect loop escaped configured bound")

    def _request_once(
        self,
        method: str,
        parsed: SplitResult,
        headers: Mapping[str, str],
        *,
        deadline: float,
    ) -> MediatedResponse:
        hostname = parsed.hostname or ""
        port = parsed.port or 443
        endpoints = self._resolve(hostname, port, deadline=deadline)
        address_set = self._address_set(endpoints)
        self._scope_guard.check_resolved_destination(hostname, tuple(sorted(address_set)))
        if not endpoints:
            raise EgressMediationError("destination did not resolve to a usable endpoint")

        endpoint = endpoints[0]
        try:
            connection = self._connector.open(
                endpoint,
                hostname=hostname,
                port=port,
                timeout_seconds=_remaining_seconds(deadline),
            )
            _remaining_seconds(deadline)
        except EgressMediationError:
            raise
        except Exception as err:
            raise EgressMediationError("HTTPS connection to the validated endpoint failed") from err

        response: MediatedResponse
        try:
            try:
                peer_ip = _canonical_ip(connection.peer_ip)
            except Exception as err:
                raise EgressMediationError("connected peer address is unavailable or invalid") from err
            if peer_ip != endpoint.ip:
                raise EgressMediationError("connected peer address differs from the validated endpoint")

            pinned_endpoints = self._resolve(hostname, port, deadline=deadline)
            pinned_address_set = self._address_set(pinned_endpoints)
            self._scope_guard.check_resolved_destination(hostname, tuple(sorted(pinned_address_set)))
            if pinned_address_set != address_set:
                raise EgressMediationError("DNS address set changed between validation and request dispatch")

            try:
                _remaining_seconds(deadline)
                identity = self._identity_verifier.verify(
                    hostname=hostname,
                    peer_certificate_der=connection.peer_certificate_der,
                    peer_certificate=connection.peer_certificate,
                )
                _remaining_seconds(deadline)
            except AuthenticatedResourceScopeError:
                raise
            except Exception as err:
                raise AuthenticatedResourceScopeError("TLS peer resource identity verification failed") from err
            host_literal = f"[{hostname}]" if ":" in hostname else hostname
            host_header = host_literal if port == 443 else f"{host_literal}:{port}"
            outbound_headers = {"Host": host_header, **headers}
            target = _request_target(parsed)
            self._identity_allowlist.require(identity, request_target=target)
            try:
                status, response_headers, body = connection.request(
                    method=method,
                    target=target,
                    headers=outbound_headers,
                    max_response_bytes=self._max_response_bytes,
                    max_response_header_bytes=self._max_response_header_bytes,
                    timeout_seconds=_remaining_seconds(deadline),
                )
                _remaining_seconds(deadline)
            except EgressMediationError:
                raise
            except Exception as err:
                raise EgressMediationError("mediated HTTPS request failed") from err
            checked_status, checked_response_headers, checked_body = self._validate_response(
                status,
                response_headers,
                body,
            )
            response = MediatedResponse(
                status=checked_status,
                headers=checked_response_headers,
                body=checked_body,
                final_url=parsed.geturl(),
                identity=identity,
            )
        except Exception:
            with suppress(Exception):
                connection.close()
            raise
        try:
            connection.close()
        except Exception as err:
            raise EgressMediationError("HTTPS connection cleanup failed") from err
        _remaining_seconds(deadline)
        return response

    def _resolve(self, hostname: str, port: int, *, deadline: float) -> tuple[ResolvedEndpoint, ...]:
        _remaining_seconds(deadline)
        try:
            endpoints = self._resolver(hostname, port)
        except EgressMediationError:
            raise
        except Exception as err:
            raise EgressMediationError("destination DNS resolution failed") from err
        _remaining_seconds(deadline)
        if not isinstance(endpoints, tuple):
            raise EgressMediationError("destination DNS resolver returned an invalid result")
        return endpoints

    @staticmethod
    def _address_set(endpoints: tuple[ResolvedEndpoint, ...]) -> frozenset[str]:
        try:
            addresses = _address_set(endpoints)
        except (AttributeError, TypeError, ValueError) as err:
            raise EgressMediationError("destination DNS resolver returned an invalid address") from err
        metadata_addresses = frozenset(_canonical_ip(address) for address in METADATA_ADDRESSES)
        if addresses & metadata_addresses:
            raise ScopeViolationError("execution egress to cloud metadata is strictly blocked")
        return addresses

    def _validate_url(self, url: str) -> SplitResult:
        if (
            not isinstance(url, str)
            or not url
            or "\\" in url
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in url)
        ):
            raise EgressProtocolError("destination URL must contain only visible ASCII characters")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as err:
            raise EgressProtocolError("destination URL contains an invalid port or address") from err
        if parsed.scheme != "https" or not parsed.hostname:
            raise EgressProtocolError("egress broker permits only absolute HTTPS URLs")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise EgressProtocolError("destination URL cannot contain user information or a fragment")
        if url.endswith("?"):
            raise EgressProtocolError("destination URL request target is not canonical")
        if port is not None and not 1 <= port <= 65535:
            raise EgressProtocolError("destination URL port is outside the valid range")
        try:
            _request_target(parsed)
        except ValueError as err:
            raise EgressProtocolError("destination URL request target is not canonical") from err
        return parsed

    def _validate_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(headers, Mapping):
            raise EgressProtocolError("request headers must be a string mapping")
        checked: dict[str, str] = {}
        seen_names: set[str] = set()
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise EgressProtocolError("request headers must be a string mapping")
            lower_name = name.lower()
            if lower_name in self._FORBIDDEN_HEADERS or lower_name.startswith("proxy-"):
                raise EgressProtocolError(f"request header '{name}' is forbidden by the egress broker")
            if not name or any(character not in _HEADER_NAME_TOKEN_CHARACTERS for character in name):
                raise EgressProtocolError("request header name is invalid")
            if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
                raise EgressProtocolError("request header value is invalid")
            if lower_name in seen_names:
                raise EgressProtocolError("request header names must be unique ignoring case")
            seen_names.add(lower_name)
            checked[name] = value
        return checked

    def _validate_response(
        self,
        status: object,
        headers: object,
        body: object,
    ) -> tuple[int, tuple[tuple[str, str], ...], bytes]:
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise EgressMediationError("mediated HTTPS response status is invalid")
        if not isinstance(headers, (tuple, list)):
            raise EgressMediationError("mediated HTTPS response headers are invalid")
        checked_headers: list[tuple[str, str]] = []
        for item in headers:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise EgressMediationError("mediated HTTPS response headers are invalid")
            name, value = item
            if (
                not isinstance(name, str)
                or not name
                or any(character not in _HEADER_NAME_TOKEN_CHARACTERS for character in name)
                or not isinstance(value, str)
                or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
            ):
                raise EgressMediationError("mediated HTTPS response headers are invalid")
            checked_headers.append((name, value))
        metadata_bytes = len(f"HTTP/1.1 {status}\r\n".encode("ascii")) + 2
        metadata_bytes += sum(
            len(name.encode("ascii")) + 2 + len(value.encode("ascii")) + 2
            for name, value in checked_headers
        )
        if metadata_bytes > self._max_response_header_bytes:
            raise EgressMediationError("mediated HTTPS response metadata exceeded the configured byte limit")
        if not isinstance(body, bytes):
            raise EgressMediationError("mediated HTTPS response body is invalid")
        if len(body) > self._max_response_bytes:
            raise EgressMediationError("mediated HTTPS response body exceeded the configured byte limit")
        return status, tuple(checked_headers), body


class _BrokerSupervisor:
    """Reap one killable broker process at its absolute operation deadline."""

    def __init__(
        self,
        *,
        process: BaseProcess,
        server_socket: socket.socket,
        observation_reader: Connection,
        mediator: HTTPSExecutionMediator,
        deadline: float,
    ) -> None:
        self._process = process
        self._server_socket = server_socket
        self._observation_reader = observation_reader
        self._mediator = mediator
        self._deadline = deadline
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._finalized = False
        self._error: EgressMediationError | None = None
        self._thread = threading.Thread(target=self._monitor, daemon=True, name="cops-egress-supervisor")
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._process.join(timeout=0.25)
        self._finish(terminate=self._process.is_alive(), send_timeout_error=False)
        self._thread.join(timeout=2)
        if self._thread.is_alive():
            raise EgressMediationError("egress broker supervisor did not terminate after adapter exit")
        if self._error is not None:
            raise self._error

    def _monitor(self) -> None:
        while not self._stop.is_set():
            remaining = self._deadline - monotonic()
            if remaining <= 0:
                self._finish(terminate=True, send_timeout_error=True)
                return
            self._process.join(timeout=min(0.02, remaining))
            if not self._process.is_alive():
                self._finish(terminate=False, send_timeout_error=False)
                return

    def _finish(self, *, terminate: bool, send_timeout_error: bool) -> None:
        with self._lock:
            if self._finalized:
                return
            if terminate and self._process.is_alive():
                self._process.kill()
            self._process.join(timeout=2)
            if self._process.is_alive():
                self._error = EgressMediationError("egress broker process could not be reaped")
            if send_timeout_error:
                with suppress(BrokenPipeError, ConnectionError, OSError, TimeoutError):
                    self._server_socket.settimeout(0.1)
                    self._server_socket.sendall(_json_line({"ok": False, "error": "egress_denied"}))
            self._merge_observations()
            self._observation_reader.close()
            self._server_socket.close()
            self._finalized = True

    def _merge_observations(self) -> None:
        while self._observation_reader.poll():
            try:
                observations = self._observation_reader.recv()
            except EOFError:
                return
            if isinstance(observations, tuple) and all(
                isinstance(observation, EgressObservation) for observation in observations
            ):
                self._mediator.observations.extend(observations)


@dataclass
class BrokerChannel:
    environment: Mapping[str, str]
    pass_fds: tuple[int, ...]
    _client_socket: socket.socket
    _supervisor: _BrokerSupervisor
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._client_socket.close()
        self._supervisor.close()


class ExecutionEgressBroker:
    """Expose a mediator to one adapter through a bounded inherited socketpair."""

    def __init__(
        self,
        mediator: HTTPSExecutionMediator,
        *,
        max_request_bytes: int = 65_536,
        max_requests: int = 8,
        max_total_request_bytes: int = 262_144,
        max_total_response_bytes: int = 8_388_608,
        protocol_timeout_seconds: float = 15.0,
    ) -> None:
        if (
            max_request_bytes <= 0
            or max_requests <= 0
            or max_total_request_bytes < max_request_bytes
            or max_total_response_bytes <= 0
            or protocol_timeout_seconds <= 0
        ):
            raise ValueError("broker operation limits must be positive and internally consistent")
        self._mediator = mediator
        self._max_request_bytes = max_request_bytes
        self._max_requests = max_requests
        self._max_total_request_bytes = max_total_request_bytes
        self._max_total_response_bytes = max_total_response_bytes
        self._protocol_timeout_seconds = protocol_timeout_seconds

    @contextmanager
    def open_channel(self, *, deadline: float | None = None) -> Iterator[BrokerChannel]:
        if "fork" not in multiprocessing.get_all_start_methods():
            raise EgressMediationError("egress broker requires a process runtime with fork support")
        protocol_deadline = monotonic() + self._protocol_timeout_seconds
        if deadline is not None:
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
                raise ValueError("egress broker deadline must be a finite monotonic timestamp")
            protocol_deadline = min(protocol_deadline, deadline)
        if protocol_deadline <= monotonic():
            raise EgressMediationError("egress broker operation deadline has expired")
        process_context = multiprocessing.get_context("fork")
        server_socket, client_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        observation_reader, observation_writer = process_context.Pipe(duplex=False)
        process = process_context.Process(
            target=self._serve_child,
            args=(server_socket, client_socket, observation_reader, observation_writer, protocol_deadline),
            daemon=True,
            name="cops-egress-broker",
        )
        process.start()
        observation_writer.close()
        supervisor = _BrokerSupervisor(
            process=process,
            server_socket=server_socket,
            observation_reader=observation_reader,
            mediator=self._mediator,
            deadline=protocol_deadline,
        )
        channel = BrokerChannel(
            environment=MappingProxyType({BROKER_FD_ENV: str(client_socket.fileno())}),
            pass_fds=(client_socket.fileno(),),
            _client_socket=client_socket,
            _supervisor=supervisor,
        )
        try:
            yield channel
        finally:
            channel.close()

    def _serve_child(
        self,
        server_socket: socket.socket,
        client_socket: socket.socket,
        observation_reader: Connection,
        observation_writer: Connection,
        deadline: float,
    ) -> None:
        client_socket.close()
        observation_reader.close()
        initial_observation_count = len(self._mediator.observations)
        try:
            self._serve(server_socket, deadline=deadline)
        finally:
            observations = tuple(self._mediator.observations[initial_observation_count:])
            with suppress(BrokenPipeError, EOFError, OSError):
                observation_writer.send(observations)
            observation_writer.close()
            server_socket.close()

    def _serve(self, server_socket: socket.socket, *, deadline: float) -> None:
        request_count = 0
        total_request_bytes = 0
        total_response_bytes = 0
        buffer = b""
        try:
            while True:
                line, buffer = self._read_line(server_socket, buffer, deadline)
                if line is None:
                    return
                request_count += 1
                total_request_bytes += len(line)
                if request_count > self._max_requests or total_request_bytes > self._max_total_request_bytes:
                    self._write_error(server_socket, "operation_limit_exceeded", deadline)
                    return
                try:
                    response = self._dispatch(line, deadline=deadline)
                    payload = {
                        "ok": True,
                        "status": response.status,
                        "headers": list(response.headers),
                        "body_base64": base64.b64encode(response.body).decode("ascii"),
                        "final_url": response.final_url,
                        "identity": response.identity.as_dict(),
                    }
                    response_line = _json_line(payload)
                    if total_response_bytes + len(response_line) > self._max_total_response_bytes:
                        self._write_error(server_socket, "operation_limit_exceeded", deadline)
                        return
                    self._send(server_socket, response_line, deadline)
                    total_response_bytes += len(response_line)
                except Exception:
                    # The broker is a trust boundary. Unexpected adapter,
                    # resolver, TLS, response, or encoding failures become a
                    # generic denial without exposing exception details.
                    self._write_error(server_socket, "egress_denied", deadline)
                    return
        except (BrokenPipeError, ConnectionError, OSError, TimeoutError):
            return

    def _read_line(
        self,
        server_socket: socket.socket,
        buffer: bytes,
        deadline: float,
    ) -> tuple[bytes | None, bytes]:
        while b"\n" not in buffer:
            if len(buffer) > self._max_request_bytes:
                self._write_error(server_socket, "request_too_large", deadline)
                raise EgressProtocolError("broker request exceeded the configured byte limit")
            server_socket.settimeout(self._remaining(deadline))
            chunk = server_socket.recv(min(65_536, self._max_request_bytes + 1 - len(buffer)))
            if not chunk:
                return None, b""
            buffer += chunk
        line, remainder = buffer.split(b"\n", 1)
        line += b"\n"
        if len(line) > self._max_request_bytes:
            self._write_error(server_socket, "request_too_large", deadline)
            raise EgressProtocolError("broker request exceeded the configured byte limit")
        return line, remainder

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("egress broker protocol deadline exceeded")
        return remaining

    def _send(self, server_socket: socket.socket, payload: bytes, deadline: float) -> None:
        server_socket.settimeout(self._remaining(deadline))
        server_socket.sendall(payload)

    def _dispatch(self, line: bytes, *, deadline: float) -> MediatedResponse:
        document = json.loads(line)
        if not isinstance(document, dict) or set(document) != {"version", "method", "url", "headers"}:
            raise EgressProtocolError("broker request fields do not match the protocol")
        if document["version"] != BROKER_PROTOCOL:
            raise EgressProtocolError("unsupported broker protocol version")
        method = document["method"]
        url = document["url"]
        headers = document["headers"]
        if not isinstance(method, str) or not isinstance(url, str) or not isinstance(headers, dict):
            raise EgressProtocolError("broker request types do not match the protocol")
        if any(not isinstance(name, str) or not isinstance(value, str) for name, value in headers.items()):
            raise EgressProtocolError("broker request header types do not match the protocol")
        return self._mediator.request(method=method, url=url, headers=headers, deadline=deadline)

    def _write_error(self, server_socket: socket.socket, code: str, deadline: float) -> None:
        self._send(server_socket, _json_line({"ok": False, "error": code}), deadline)


def _default_resolver(hostname: str, port: int) -> tuple[ResolvedEndpoint, ...]:
    try:
        results = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise EgressMediationError("destination DNS resolution failed") from err
    endpoints: list[ResolvedEndpoint] = []
    seen: set[tuple[int, str, int]] = set()
    for family, socktype, proto, _canonical_name, sockaddr in results:
        ip = _canonical_ip(sockaddr[0])
        key = (family, ip, port)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(
            ResolvedEndpoint(
                family=family,
                socktype=socktype,
                proto=proto,
                sockaddr=tuple(sockaddr),
                ip=ip,
            )
        )
    if not endpoints:
        raise EgressMediationError("destination DNS resolution returned no usable addresses")
    return tuple(endpoints)


def _request_target(parsed: SplitResult) -> str:
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return _validate_configured_request_target(target)


def _validate_configured_request_target(target: object) -> str:
    """Require one unambiguous origin-form target for exact resource binding."""

    if (
        not isinstance(target, str)
        or not target
        or not target.startswith("/")
        or target.startswith("//")
        or "\\" in target
        or "%" in target
        or "#" in target
        or target.endswith("?")
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in target)
    ):
        raise ValueError("authenticated service request target must be canonical visible ASCII origin-form")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("authenticated service request target must be origin-form")
    if any(segment in {".", ".."} for segment in parsed.path.split("/")):
        raise ValueError("authenticated service request target cannot contain dot segments")
    canonical = parsed.path or "/"
    if parsed.query:
        canonical = f"{canonical}?{parsed.query}"
    if canonical != target:
        raise ValueError("authenticated service request target must be canonical")
    return target


def _canonical_ip(value: str) -> str:
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    return str(parsed)


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise EgressMediationError("mediated HTTPS operation exceeded the configured deadline")
    return remaining


def _address_set(endpoints: tuple[ResolvedEndpoint, ...]) -> frozenset[str]:
    return frozenset(_canonical_ip(endpoint.ip) for endpoint in endpoints)


def _required_single_header(headers: tuple[tuple[str, str], ...], name: str) -> str:
    values = [value for header_name, value in headers if header_name.lower() == name.lower()]
    if not values:
        raise EgressProtocolError(f"redirect response is missing the required {name} header")
    if len(values) != 1:
        raise EgressProtocolError(f"redirect response carries multiple {name} headers")
    if not values[0]:
        raise EgressProtocolError(f"redirect response carries an empty {name} header")
    return values[0]


def _redacted_origin(url: str) -> str:
    """Return only the request origin; never persist paths, queries, or user data."""

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return "unparseable"
    if parsed.scheme not in {"http", "https"} or not hostname:
        return "unparseable"
    host_literal = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme == "https" else 80
    port_suffix = "" if port in {None, default_port} else f":{port}"
    return f"{parsed.scheme}://{host_literal}{port_suffix}"


def _json_line(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


_HEADER_NAME_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
