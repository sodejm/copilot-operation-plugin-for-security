"""Disposable seven-family service-validation journey for operator acceptance.

This module deliberately binds every endpoint to loopback.  Its adapters prove
the public discovery-to-report boundary without claiming support for arbitrary
or external services.
"""

from __future__ import annotations

import os
import secrets
import socket
import socketserver
import struct
import threading
import time
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from cops.assessment_budget import AssessmentBudgetLedger, AttemptRequest, BudgetLimits, BudgetPolicy
from cops.evidence.canonical import utc_now
from cops.execution.filesystem import SecureDirectoryError, create_directory_exclusive_no_symlinks

from .active_models import ActiveScanSession, ActiveServiceAssessment, ObservedConfiguration, active_assessment_digest
from .models import EvidenceProvenance
from .service_entry_validation import ApprovedEndpoint, ServiceValidationPlan, prepare_session_service_handoffs
from .service_validation_execution import (
    AuthorizationReceipt,
    ValidationActionResult,
    ValidationDispatchContext,
    ValidationEvidenceVerification,
    ValidationProbeOutput,
    ValidationSelection,
    execute_service_validation_action,
    load_trusted_issue_143_reproduction,
)

_STANDARD_PORTS = frozenset({22, 25, 53, 80, 1080, 2375, 6379})
_DIMENSIONS = ("exposure", "authentication", "configuration", "version", "trust")
_AUDIT_PREFIX = b"COPS-AUDIT "
_MAX_AUDIT_HEADER_BYTES = 1024
_MAX_AUDIT_REQUEST_BYTES = 8192
_AUDIT_COMPLETION_TIMEOUT_SECONDS = 2.0


def _read_audit_frame(connection: socket.socket, initial: bytes = _AUDIT_PREFIX) -> tuple[str, str, bytes]:
    frame = bytearray(initial)
    while b"\n" not in frame:
        if len(frame) >= _MAX_AUDIT_HEADER_BYTES:
            raise ValueError("fixture audit header exceeds the bounded limit")
        chunk = connection.recv(1)
        if not chunk:
            raise ValueError("fixture audit header ended before the newline delimiter")
        frame.extend(chunk)
    header, request = bytes(frame).split(b"\n", 1)
    parts = header.split(b" ")
    if len(parts) != 4 or parts[0] != b"COPS-AUDIT":
        raise ValueError("fixture audit header is malformed")
    audit_reference = parts[1].decode("ascii", errors="strict")
    correlation_id = parts[2].decode("ascii", errors="strict")
    request_length_text = parts[3].decode("ascii", errors="strict")
    if not request_length_text.isdecimal() or (request_length_text != "0" and request_length_text.startswith("0")):
        raise ValueError("fixture audit request length is not canonical")
    request_length = int(request_length_text)
    if request_length > _MAX_AUDIT_REQUEST_BYTES:
        raise ValueError("fixture audit request exceeds the bounded limit")
    if len(request) > request_length:
        raise ValueError("fixture audit frame contains trailing bytes")
    while len(request) < request_length:
        chunk = connection.recv(request_length - len(request))
        if not chunk:
            raise ValueError("fixture audit request ended before its declared length")
        request += chunk
    return audit_reference, correlation_id, request


def _read_wire_request(connection: socket.socket) -> tuple[str, str, bytes]:
    probe = bytearray()
    while len(probe) < len(_AUDIT_PREFIX):
        chunk = connection.recv(1)
        if not chunk:
            return "", "", bytes(probe)
        probe.extend(chunk)
        if not _AUDIT_PREFIX.startswith(probe):
            try:
                probe.extend(connection.recv(4096 - len(probe)))
            except TimeoutError:
                pass
            return "", "", bytes(probe)
    return _read_audit_frame(connection, bytes(probe))


@dataclass(frozen=True)
class LabServiceAdapter:
    service: str
    skill_id: str
    family: str
    protocol: str
    evidence_scope: str = "disposable loopback fixture only"


_ADAPTERS = (
    LabServiceAdapter("http", "web-api-inventory-and-replay", "web API", "HTTP"),
    LabServiceAdapter("ssh", "network-remote-and-file-services", "remote and file", "SSH"),
    LabServiceAdapter("redis", "network-data-services", "data", "Redis"),
    LabServiceAdapter("smtp", "network-messaging-services", "messaging", "SMTP"),
    LabServiceAdapter("docker-api", "network-developer-interfaces", "developer interface", "Docker API"),
    LabServiceAdapter("dns", "network-infrastructure-services", "infrastructure", "DNS over TCP"),
    LabServiceAdapter("socks", "network-legacy-and-proxy-services", "legacy and proxy", "SOCKS"),
)


def lab_service_provider_registry() -> tuple[LabServiceAdapter, ...]:
    """Return the explicit lab-only adapter registry for the seven routed families."""
    return _ADAPTERS


@dataclass(frozen=True)
class _Case:
    case_id: str
    service: str
    banner: bytes
    version: str
    expected_status: str = "completed"
    candidate: bool = False
    incomplete: bool = False


_CASES = (
    _Case(
        "http-insufficient",
        "http",
        b"HTTP/1.1 200 OK\r\nServer: Lab/1.0\r\nContent-Length: 0\r\n\r\n",
        "lab-http-1.0",
        "insufficient_evidence",
        incomplete=True,
    ),
    _Case("ssh-benign", "ssh", b"SSH-2.0-Lab_9.0\r\n", "lab-ssh-9.0"),
    _Case("redis-candidate", "redis", b"-ERR Redis 5.0 no password configured\r\n", "redis-lab-5.0", candidate=True),
    _Case("smtp-benign", "smtp", b"220 lab ESMTP Postfix\r\n", "lab-smtp-1.0"),
    _Case("docker-benign", "docker-api", b'{"ApiVersion":"1.43","Version":"24.0"}\r\n', "lab-docker-24.0"),
    _Case("dns-benign", "dns", b"DNS response lab-authoritative-1.0\r\n", "lab-dns-1.0"),
    _Case("socks-benign", "socks", b"SOCKS5 lab-proxy-1.0\r\n", "lab-socks-5"),
    _Case(
        "redis-remediated",
        "redis",
        b"-ERR Redis 7.2 authentication required; remediated\r\n",
        "redis-lab-7.2-protected",
    ),
)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        audit_reference = ""
        pending: dict[str, object] | None = None
        request = b""
        response = b""
        banner = b""
        with server.audit_lock:  # type: ignore[attr-defined]
            server.connection_count += 1  # type: ignore[attr-defined]
        try:
            self.request.settimeout(0.5)
            service = server.case.service  # type: ignore[attr-defined]
            if service in {"ssh", "smtp"}:
                banner = server.banner  # type: ignore[attr-defined]
                self.request.sendall(banner)
            try:
                audit_reference, correlation_id, request = _read_wire_request(self.request)
            except TimeoutError:
                correlation_id = ""
                request = b""
            if audit_reference:
                with server.audit_lock:  # type: ignore[attr-defined]
                    candidate = server.pending_audits.pop(audit_reference, None)  # type: ignore[attr-defined]
                if candidate is not None and secrets.compare_digest(
                    str(candidate["dispatch_correlation_id"]), correlation_id
                ):
                    pending = candidate
                else:
                    request = b""
            response = _fixture_response(server.case, request)  # type: ignore[attr-defined]
            if response:
                self.request.sendall(response)
        finally:
            with server.audit_lock:  # type: ignore[attr-defined]
                if request:
                    server.requests.append(request)  # type: ignore[attr-defined]
                if banner:
                    server.responses.append(banner)  # type: ignore[attr-defined]
                if response:
                    server.responses.append(response)  # type: ignore[attr-defined]
                if pending is not None:
                    server.closing_audits[self.request] = (  # type: ignore[attr-defined]
                        audit_reference,
                        {
                            **pending,
                            "banner": banner,
                            "request": request,
                            "response": response,
                        },
                    )


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, case: _Case) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.case = case
        self.banner = case.banner
        self.connection_count = 0
        self.closed_connections = 0
        self.requests: list[bytes] = []
        self.responses: list[bytes] = []
        self.audit_lock = threading.Lock()
        self.audit_condition = threading.Condition(self.audit_lock)
        self.pending_audits: dict[str, dict[str, object]] = {}
        self.audit: dict[str, dict[str, object]] = {}
        self.closing_audits: dict[socket.socket, tuple[str, dict[str, object]]] = {}
        self.active_requests: dict[threading.Thread, socket.socket] = {}
        self.worker_failures: list[str] = []

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        # Register before starting the daemon worker so shutdown cannot miss a
        # newly accepted request that has not entered its handler yet.
        worker = threading.Thread(target=self.process_request_thread, args=(request, client_address), daemon=True)
        with self.audit_lock:
            self.active_requests[worker] = request
        try:
            worker.start()
        except Exception:
            with self.audit_lock:
                self.active_requests.pop(worker, None)
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        except Exception as exc:
            with self.audit_lock:
                self.worker_failures.append(type(exc).__name__)
            try:
                request.close()
            except OSError:
                pass
        finally:
            with self.audit_lock:
                self.active_requests.pop(threading.current_thread(), None)

    def shutdown_request(self, request: socket.socket) -> None:
        # ThreadingMixIn invokes this after the handler returns. An audit may
        # attest closure only after the transport has actually been closed.
        super().shutdown_request(request)
        if request.fileno() != -1:
            raise RuntimeError("fixture transport remained open")
        with self.audit_condition:
            pending = self.closing_audits.pop(request, None)
            if pending is not None:
                audit_reference, record = pending
                self.audit[audit_reference] = {**record, "recorded_at": utc_now(), "closed": True}
            self.closed_connections += 1
            self.audit_condition.notify_all()

    def read_completed_audit(
        self,
        audit_reference: str,
        *,
        timeout: float = _AUDIT_COMPLETION_TIMEOUT_SECONDS,
    ) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        with self.audit_condition:
            while True:
                record = self.audit.get(audit_reference)
                if record is not None and record.get("closed") is True:
                    self.audit.pop(audit_reference, None)
                    return dict(record)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.audit_condition.wait(timeout=remaining)
        raise RuntimeError("provider transaction audit record was unavailable")

    def issue_audit_reference(self, metadata: dict[str, object]) -> str:
        with self.audit_lock:
            while True:
                audit_reference = secrets.token_urlsafe(32)
                if audit_reference not in self.pending_audits and audit_reference not in self.audit:
                    self.pending_audits[audit_reference] = dict(metadata)
                    return audit_reference

    def discard_pending_audit(self, audit_reference: str) -> None:
        with self.audit_lock:
            self.pending_audits.pop(audit_reference, None)


@dataclass
class _RunningFixture:
    case: _Case
    server: _Server
    thread: threading.Thread

    @property
    def endpoint(self) -> ApprovedEndpoint:
        return ApprovedEndpoint("127.0.0.1", "127.0.0.1", self.server.server_address[1], "tcp", "internal")

    def stop(self) -> None:
        failure: Exception | None = None
        try:
            self.server.shutdown()
        except Exception as exc:
            failure = exc
        with self.server.audit_lock:
            active = tuple(self.server.active_requests.items())
        for _, request in active:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            self.server.server_close()
        except Exception as exc:
            failure = failure or exc
        self.thread.join(timeout=2)
        deadline = time.monotonic() + 2
        for worker, _ in active:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        with self.server.audit_lock:
            workers_remaining = bool(self.server.active_requests)
            workers_failed = bool(self.server.worker_failures)
        if self.thread.is_alive() or workers_remaining or workers_failed or failure is not None:
            raise RuntimeError(f"fixture {self.case.case_id} did not stop cleanly") from failure


def _start_fixture(case: _Case) -> _RunningFixture:
    while True:
        server = _Server(case)
        if server.server_address[1] not in _STANDARD_PORTS:
            break
        server.server_close()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return _RunningFixture(case, server, thread)


def _fixture_response(case: _Case, request: bytes) -> bytes:
    if case.service == "http" and request.startswith(b"GET /health HTTP/1.1\r\n"):
        return case.banner
    if case.service == "docker-api" and request.startswith(b"GET /version HTTP/1.1\r\n"):
        body = case.banner.rstrip(b"\r\n")
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )
    if case.service == "redis":
        if request == b"PING\r\nECHO authorized-use\r\n" and case.candidate:
            return b"+PONG\r\n+AUTHORIZED\r\n"
        if request == b"PING\r\n":
            return b"+PONG\r\n" if case.candidate else b"-NOAUTH Authentication required.\r\n"
        if request == b"ECHO authorized-use\r\n" and case.candidate:
            return b"+AUTHORIZED\r\n"
    if case.service == "smtp" and request.startswith(b"EHLO loopback.invalid\r\n"):
        return b"250-lab\r\n250 HELP\r\n"
    if case.service == "dns" and len(request) >= 14:
        (size,) = struct.unpack("!H", request[:2])
        query = request[2 : 2 + size]
        if len(query) == size and len(query) >= 12:
            response = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]
            return struct.pack("!H", len(response)) + response
    if case.service == "socks" and request == b"\x05\x01\x00":
        return b"\x05\x00"
    return b""


def _recv_all(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            chunk = connection.recv(1024)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _dns_query() -> bytes:
    question = b"\x03lab\x07invalid\x00\x00\x01\x00\x01"
    query = b"\xc0\x25\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    return struct.pack("!H", len(query)) + query


def _request_for(service: str, *, controlled_proof: bool) -> bytes:
    return {
        "ssh": b"",
        "smtp": b"EHLO loopback.invalid\r\n",
        "http": b"GET /health HTTP/1.1\r\nHost: loopback.invalid\r\nConnection: close\r\n\r\n",
        "docker-api": b"GET /version HTTP/1.1\r\nHost: loopback.invalid\r\nConnection: close\r\n\r\n",
        "dns": _dns_query(),
        "socks": b"\x05\x01\x00",
        "redis": b"PING\r\nECHO authorized-use\r\n" if controlled_proof else b"PING\r\n",
    }[service]


def _protocol_for(service: str, *, controlled_proof: bool) -> str:
    return {
        "ssh": "SSH identification exchange",
        "smtp": "SMTP EHLO exchange",
        "http": "HTTP GET /health response",
        "docker-api": "Docker Engine GET /version response",
        "dns": "DNS-over-TCP query response",
        "socks": "SOCKS5 method negotiation",
        "redis": "Redis controlled proof" if controlled_proof else "Redis PING response",
    }[service]


def _probe(
    endpoint: ApprovedEndpoint,
    service: str,
    *,
    controlled_proof: bool = False,
    audit_reference: str = "",
    dispatch_correlation_id: str = "",
) -> tuple[str, str]:
    request = _request_for(service, controlled_proof=controlled_proof)
    wire_request = request
    if audit_reference:
        wire_request = (
            _AUDIT_PREFIX
            + audit_reference.encode("ascii")
            + b" "
            + dispatch_correlation_id.encode("ascii")
            + b" "
            + str(len(request)).encode("ascii")
            + b"\n"
            + request
        )
    with socket.create_connection((endpoint.resolved_ip, endpoint.port), timeout=2) as connection:
        connection.settimeout(1)
        if service == "ssh":
            raw = connection.recv(1024)
            connection.sendall(wire_request)
            connection.shutdown(socket.SHUT_WR)
            _recv_all(connection)
            if not raw.startswith(b"SSH-2.0-"):
                raise RuntimeError("invalid SSH identification string")
            return raw.decode("ascii", errors="replace").strip(), _protocol_for(service, controlled_proof=False)
        if service == "smtp":
            banner = connection.recv(1024)
            connection.sendall(wire_request)
            response = _recv_all(connection)
            if not banner.startswith(b"220 ") or not response.startswith(b"250-"):
                raise RuntimeError("invalid SMTP greeting or EHLO response")
            return (
                (banner + response).decode("ascii", errors="replace").strip(),
                _protocol_for(service, controlled_proof=False),
            )
        if service == "http":
            connection.sendall(wire_request)
            raw = _recv_all(connection)
            if not raw.startswith(b"HTTP/1.1 200 OK\r\n"):
                raise RuntimeError("invalid HTTP response")
            return raw.decode("ascii", errors="replace").strip(), _protocol_for(service, controlled_proof=False)
        if service == "docker-api":
            connection.sendall(wire_request)
            raw = _recv_all(connection)
            if not raw.startswith(b"HTTP/1.1 200 OK\r\n") or b'"ApiVersion":"1.43"' not in raw:
                raise RuntimeError("invalid Docker Engine /version response")
            return (
                raw.decode("ascii", errors="replace").strip(),
                _protocol_for(service, controlled_proof=False),
            )
        if service == "dns":
            query = request
            connection.sendall(wire_request)
            raw = _recv_all(connection)
            if len(raw) < 14 or raw[2:4] != query[2:4] or not (raw[4] & 0x80):
                raise RuntimeError("invalid DNS-over-TCP response")
            return raw.hex(), _protocol_for(service, controlled_proof=False)
        if service == "socks":
            connection.sendall(wire_request)
            raw = _recv_all(connection)
            if raw != b"\x05\x00":
                raise RuntimeError("invalid SOCKS5 method negotiation")
            return raw.hex(), _protocol_for(service, controlled_proof=False)
        if service == "redis":
            connection.sendall(wire_request)
            raw = _recv_all(connection)
            if controlled_proof and raw != b"+PONG\r\n+AUTHORIZED\r\n":
                raise RuntimeError("invalid Redis controlled-proof response")
            if not controlled_proof and not (raw == b"+PONG\r\n" or raw.startswith(b"-NOAUTH ")):
                raise RuntimeError("invalid Redis PING response")
            return (
                raw.decode("ascii", errors="replace").strip(),
                _protocol_for(service, controlled_proof=controlled_proof),
            )
    raise RuntimeError(f"unsupported lab service: {service}")


class _Provider:
    def __init__(self, fixture: _RunningFixture) -> None:
        self.fixture = fixture
        self.case = fixture.case

    def __call__(
        self, plan: ServiceValidationPlan, action: str, context: ValidationDispatchContext
    ) -> ValidationProbeOutput:
        controlled_proof = action == "controlled_proof"
        request = _request_for(self.case.service, controlled_proof=controlled_proof)
        protocol = _protocol_for(self.case.service, controlled_proof=controlled_proof)
        audit_reference = self.fixture.server.issue_audit_reference(
            {
                "plan_id": plan.plan_id,
                "attempt_id": context.attempt_id,
                "approval_receipt_id": context.approval_receipt_id,
                "action": action,
                "endpoint": asdict(plan.endpoint),
                "dispatch_correlation_id": context.correlation_id,
                "service": self.case.service,
                "protocol": protocol,
                "expected_request": request,
            }
        )
        try:
            evidence, protocol = _probe(
                plan.endpoint,
                self.case.service,
                controlled_proof=controlled_proof,
                audit_reference=audit_reference,
                dispatch_correlation_id=context.correlation_id,
            )
        except Exception:
            self.fixture.server.discard_pending_audit(audit_reference)
            raise
        response = "+PONG" if action == "controlled_proof" and self.case.service == "redis" else ""
        trusted = load_trusted_issue_143_reproduction(plan.endpoint)
        return ValidationProbeOutput(
            protocol_evidence=(f"provider {protocol} sha256 {sha256(evidence.encode()).hexdigest()}",),
            dimensions={dimension: "provider supplied; independently verified below" for dimension in _DIMENSIONS},
            candidate=self.case.candidate,
            audit_reference=audit_reference,
            effect_evidence=((f"provider PING response: {response}",) if response else ()),
            proof_succeeded=response == "+PONG",
            cleanup_evidence=("provider connection closed",),
            reproduction=trusted.reproduction if self.case.candidate else None,
            finding=trusted.finding if self.case.candidate else None,
            tokens=5,
            cost_microunits=50,
            retained_output_bytes=256,
        )


class _Verifier:
    def __init__(self, fixture: _RunningFixture) -> None:
        self.fixture = fixture
        self.case = fixture.case

    def _read_audit(self, audit_reference: str) -> dict[str, object]:
        return self.fixture.server.read_completed_audit(audit_reference)

    def __call__(
        self,
        plan: ServiceValidationPlan,
        selection: ValidationSelection,
        approval: AuthorizationReceipt,
        output: ValidationProbeOutput,
        context: ValidationDispatchContext,
    ) -> ValidationEvidenceVerification:
        audit = self._read_audit(output.audit_reference)
        controlled_proof = selection.action == "controlled_proof"
        expected_request = _request_for(self.case.service, controlled_proof=controlled_proof)
        expected_protocol = _protocol_for(self.case.service, controlled_proof=controlled_proof)
        expected_endpoint = asdict(plan.endpoint)
        expected_bindings = {
            "plan_id": plan.plan_id,
            "attempt_id": approval.attempt_id,
            "approval_receipt_id": approval.receipt_id,
            "action": selection.action,
            "dispatch_correlation_id": context.correlation_id,
            "service": self.case.service,
            "protocol": expected_protocol,
        }
        if (
            any(
                not isinstance(audit.get(key), str) or not secrets.compare_digest(str(audit[key]), expected)
                for key, expected in expected_bindings.items()
            )
            or audit.get("endpoint") != expected_endpoint
            or audit.get("request") != expected_request
        ):
            raise RuntimeError("fixture audit record does not bind the exact dispatched action")
        expected_banner = self.case.banner if self.case.service in {"ssh", "smtp"} else b""
        expected_response = _fixture_response(self.case, expected_request)
        if (
            audit.get("banner") != expected_banner
            or audit.get("response") != expected_response
            or audit.get("closed") is not True
        ):
            raise RuntimeError("fixture audit record does not match the exact observed transaction")
        raw = expected_banner + expected_response
        evidence = raw.hex() if self.case.service in {"dns", "socks"} else raw.decode("ascii", errors="replace").strip()
        protocol = {
            "ssh": "SSH identification exchange",
            "smtp": "SMTP EHLO exchange",
            "http": "HTTP GET /health response",
            "docker-api": "Docker Engine GET /version response",
            "dns": "DNS-over-TCP query response",
            "socks": "SOCKS5 method negotiation",
            "redis": "Redis controlled proof" if selection.action == "controlled_proof" else "Redis PING response",
        }[self.case.service]
        effect = "+PONG" if b"+PONG\r\n" in raw and selection.action == "controlled_proof" else ""
        authorized = "+AUTHORIZED" if b"+AUTHORIZED\r\n" in raw else ""
        trusted = load_trusted_issue_143_reproduction(plan.endpoint)
        incomplete = self.case.incomplete
        dimensions = (
            {}
            if incomplete
            else {
                "exposure": "independent loopback TCP response observed",
                "authentication": "read-only banner or separately authorized fixture effect observed",
                "configuration": f"fixture role {self.case.case_id} independently identified",
                "version": self.case.version,
                "trust": "disposable loopback fixture; no external trust claim",
            }
        )
        return ValidationEvidenceVerification(
            approval_receipt_id=approval.receipt_id,
            plan_id=plan.plan_id,
            attempt_id=approval.attempt_id,
            evidence_sha256=plan.evidence_sha256,
            endpoint=plan.endpoint,
            action=selection.action,
            audit_reference=output.audit_reference,
            audit_recorded_at=str(audit["recorded_at"]),
            dispatch_correlation_id=context.correlation_id,
            observed_version="" if incomplete else self.case.version,
            protocol_evidence=()
            if incomplete
            else (f"independent {protocol} sha256 {sha256(evidence.encode()).hexdigest()}",),
            dimensions=dimensions,
            verified_at=utc_now(),
            reproduction_sha256=trusted.sha256 if self.case.candidate else "",
            candidate_verified=self.case.candidate,
            finding_effect=effect,
            effect_evidence=((f"independent Redis PING response: {effect}",) if effect else ()),
            finding_effect_verified=effect == trusted.reproduction.expected_proof,
            authorized_use_evidence=((f"independent Redis ECHO response: {authorized}",) if authorized else ()),
            authorized_use_verified=authorized == "+AUTHORIZED",
            cleanup_evidence=("fixture observed connection close",),
            cleanup_verified=True,
        )


class _ApprovalGate:
    def __init__(self) -> None:
        self.receipts: list[AuthorizationReceipt] = []
        self._issued_receipt_ids: set[str] = set()

    def __call__(
        self, plan: ServiceValidationPlan, selection: ValidationSelection, attempt_id: str
    ) -> AuthorizationReceipt:
        now = datetime.now(UTC)
        receipt_id = f"lab-approval-{attempt_id}"
        if receipt_id in self._issued_receipt_ids:
            raise RuntimeError("approval receipt was already issued by this authority")
        self._issued_receipt_ids.add(receipt_id)
        receipt = AuthorizationReceipt(
            receipt_id=receipt_id,
            plan_id=plan.plan_id,
            endpoint=plan.endpoint,
            action=selection.action,
            attempt_id=attempt_id,
            engagement_id="issue-285-seven-family-lab",
            authority_id="fixture-operator",
            issued_at=(now - timedelta(seconds=1)).isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
            approved=True,
        )
        self.receipts.append(receipt)
        return receipt


def _ledger(state_directory: Path, *, directory_fd: int) -> AssessmentBudgetLedger:
    policy = BudgetPolicy(
        engagement_id="issue-285-seven-family-lab",
        limits=BudgetLimits(
            max_attempts=12,
            max_estimated_tokens=2000,
            max_estimated_cost_microunits=20_000,
            max_elapsed_ms=120_000,
            max_concurrency=2,
            max_retained_output_bytes=20_000,
            max_depth=1,
            max_children_per_parent=12,
        ),
        currency="USD",
        price_source="disposable-loopback-fixtures",
        price_version="1",
        price_effective_date="2026-10-14",
    )
    return AssessmentBudgetLedger(
        state_directory / "service-validation.sqlite3",
        policy,
        directory_fd=directory_fd,
    )


def _request(attempt_id: str) -> AttemptRequest:
    return AttemptRequest(attempt_id, None, 10, 100, 512)


def run_loopback_service_validation_journey(state_directory: Path | str) -> dict[str, Any]:
    """Run discovery, routing, evidence-gated validation, proof, and reporting locally."""
    state_path = Path(os.path.abspath(os.fspath(Path(state_directory).expanduser())))
    try:
        state_fd = create_directory_exclusive_no_symlinks(state_path, mode=0o700)
    except SecureDirectoryError as exc:
        raise ValueError("state directory must be a fresh path beneath real directories") from exc
    fixtures: list[_RunningFixture] = []
    report: dict[str, Any] | None = None
    try:
        for case in _CASES:
            fixtures.append(_start_fixture(case))
        assessments: list[ActiveServiceAssessment] = []
        endpoints: set[ApprovedEndpoint] = set()
        fixture_by_port: dict[int, _RunningFixture] = {}
        discovery_protocol_by_port: dict[int, str] = {}
        for fixture in fixtures:
            endpoint = fixture.endpoint
            endpoints.add(endpoint)
            fixture_by_port[endpoint.port] = fixture
            banner, discovery_protocol = _probe(endpoint, fixture.case.service)
            discovery_protocol_by_port[endpoint.port] = discovery_protocol
            probe_id = f"probe-{fixture.case.case_id}"
            assessment = ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=endpoint.host,
                resolved_ip=endpoint.resolved_ip,
                port=endpoint.port,
                protocol=endpoint.transport,
                vantage=endpoint.vantage,
                observed_config=ObservedConfiguration(
                    raw_banner=None if fixture.case.service in {"dns", "socks"} else banner,
                    banner_bytes=banner if fixture.case.service in {"dns", "socks"} else None,
                    http_status=200 if fixture.case.service == "http" else None,
                ),
            )
            digest = active_assessment_digest(assessment)
            assessment = replace(
                assessment,
                provenance=EvidenceProvenance(
                    source_id="issue-285-seven-family-lab",
                    source_type="active_scan",
                    sha256=digest,
                    timestamp=assessment.timestamp_utc,
                    path_or_uri="approved-disposable-loopback-only",
                    raw_record_ref=ActiveScanSession.make_probe_key(
                        assessment.vantage,
                        assessment.protocol,
                        assessment.target_host,
                        assessment.port,
                    ),
                ),
            )
            assessments.append(assessment)

        session = ActiveScanSession(
            session_id="issue-285-seven-family-lab",
            scope_reference="approved-disposable-loopback-only",
            approved_targets=["127.0.0.1"],
            approved_ports=[endpoint.port for endpoint in endpoints],
            vantage="internal",
            status="completed",
            completed_at=utc_now(),
            completed_probe_keys={
                ActiveScanSession.make_probe_key("internal", "tcp", "127.0.0.1", endpoint.port)
                for endpoint in endpoints
            },
            assessments=assessments,
            total_probes_dispatched=len(assessments),
        )
        handoffs = prepare_session_service_handoffs(session, approved_endpoints=endpoints)
        plans = [handoff.plan for handoff in handoffs if handoff.status == "candidate" and handoff.plan is not None]
        if len(plans) != len(fixtures):
            raise RuntimeError(f"routing did not produce one exact plan per endpoint: {[h.status for h in handoffs]}")

        ledger = _ledger(state_path, directory_fd=state_fd)
        gate = _ApprovalGate()
        results: list[dict[str, Any]] = []
        candidate_result: ValidationActionResult | None = None
        candidate_plan: ServiceValidationPlan | None = None
        for index, plan in enumerate(plans, start=1):
            fixture = fixture_by_port[plan.endpoint.port]
            if plan.service != fixture.case.service:
                raise RuntimeError(f"route mismatch for {fixture.case.case_id}: {plan.service}")
            attempt_id = f"lab-low-impact-{index}"
            result = execute_service_validation_action(
                plan,
                ValidationSelection(plan.plan_id, "low_impact_validation"),
                ledger=ledger,
                request=_request(attempt_id),
                authorization_gate=gate,
                provider=_Provider(fixture),
                evidence_verifier=_Verifier(fixture),
            )
            if result.status != fixture.case.expected_status:
                raise RuntimeError(f"unexpected {fixture.case.case_id} status: {result.status}")
            if fixture.case.candidate:
                candidate_result = result
                candidate_plan = plan
            results.append(
                {
                    "case_id": fixture.case.case_id,
                    "discovered": {
                        "probe_id": f"probe-{fixture.case.case_id}",
                        "endpoint": asdict(plan.endpoint),
                        "nonstandard_port": plan.endpoint.port not in _STANDARD_PORTS,
                        "protocol_evidence": discovery_protocol_by_port[plan.endpoint.port],
                    },
                    "route": {"service": plan.service, "skill_id": plan.skill_id, "status": "candidate"},
                    "investigated": bool(result.protocol_evidence),
                    "validation": asdict(result),
                }
            )

        if candidate_result is None or candidate_plan is None:
            raise RuntimeError("affected Redis candidate was not retained")
        proof_attempt = "lab-controlled-proof-9"
        proof = execute_service_validation_action(
            candidate_plan,
            ValidationSelection(candidate_plan.plan_id, "controlled_proof"),
            ledger=ledger,
            request=_request(proof_attempt),
            authorization_gate=gate,
            provider=_Provider(fixture_by_port[candidate_plan.endpoint.port]),
            evidence_verifier=_Verifier(fixture_by_port[candidate_plan.endpoint.port]),
            prerequisite_receipt=candidate_result.prerequisite_receipt,
        )
        if proof.status != "completed" or not proof.verified_finding or not proof.successful_authorized_use:
            raise RuntimeError(f"controlled proof did not verify exact effect and authorized use: {proof.status}")
        report = {
            "journey": ["discovery", "route", "investigate", "validate", "report"],
            "scope": "127.0.0.1 disposable fixtures only",
            "external_targets_supported": False,
            "registry": [asdict(adapter) for adapter in _ADAPTERS],
            "services": results,
            "controlled_proof": asdict(proof),
            "approvals": [asdict(receipt) for receipt in gate.receipts],
            "budget": asdict(ledger.snapshot()),
            "cleanup": [],
            "limitations": [
                "Adapters in this journey are lab-only and do not establish native external provider support.",
                "The HTTP case intentionally withholds independent evidence and remains insufficient.",
                "The verifier passively checks the provider transaction audit; parser diversity is not established.",
            ],
        }
    finally:
        cleanup_failures: list[str] = []
        for fixture in fixtures:
            try:
                fixture.stop()
            except Exception:
                cleanup_failures.append(fixture.case.case_id)
        os.close(state_fd)

    if cleanup_failures:
        raise RuntimeError(f"fixture cleanup failed: {', '.join(cleanup_failures)}")

    if report is None:
        raise RuntimeError("loopback journey did not produce a report")
    for _ in range(20):
        if all(f.server.closed_connections == f.server.connection_count for f in fixtures):
            break
        time.sleep(0.01)
    report["cleanup"] = [
        {
            "case_id": fixture.case.case_id,
            "stopped": not fixture.thread.is_alive(),
            "connection_count": fixture.server.connection_count,
            "closed_connections": fixture.server.closed_connections,
            "request_count": len(fixture.server.requests),
            "response_count": len(fixture.server.responses),
            "all_connections_closed": fixture.server.closed_connections == fixture.server.connection_count,
        }
        for fixture in fixtures
    ]
    if any(not item["stopped"] or not item["all_connections_closed"] for item in report["cleanup"]):
        raise RuntimeError("fixture cleanup could not confirm all connections closed")
    return report
