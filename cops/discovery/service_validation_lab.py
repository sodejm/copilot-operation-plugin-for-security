"""Disposable seven-family service-validation journey for operator acceptance.

This module deliberately binds every endpoint to loopback.  Its adapters prove
the public discovery-to-report boundary without claiming support for arbitrary
or external services.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
import time
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any

from cops.assessment_budget import AssessmentBudgetLedger, AttemptRequest, BudgetLimits, BudgetPolicy
from cops.evidence.canonical import utc_now

from .active_models import ActiveScanSession, ActiveServiceAssessment, ObservedConfiguration, active_assessment_digest
from .models import EvidenceProvenance
from .service_entry_validation import ApprovedEndpoint, ServiceValidationPlan, prepare_session_service_handoffs
from .service_validation_execution import (
    AuthorizationReceipt,
    ValidationActionResult,
    ValidationEvidenceVerification,
    ValidationProbeOutput,
    ValidationSelection,
    execute_service_validation_action,
    load_trusted_issue_143_reproduction,
)

_STANDARD_PORTS = frozenset({22, 25, 53, 80, 1080, 2375, 6379})
_DIMENSIONS = ("exposure", "authentication", "configuration", "version", "trust")


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
        server.connection_count += 1  # type: ignore[attr-defined]
        try:
            self.request.settimeout(0.5)
            service = server.case.service  # type: ignore[attr-defined]
            if service in {"ssh", "smtp"}:
                self.request.sendall(server.banner)  # type: ignore[attr-defined]
                server.responses.append(server.banner)  # type: ignore[attr-defined]
            try:
                request = self.request.recv(1024) if service != "ssh" else b""
            except TimeoutError:
                request = b""
            if request:
                server.requests.append(request)  # type: ignore[attr-defined]
            response = _fixture_response(server.case, request)  # type: ignore[attr-defined]
            if response:
                self.request.sendall(response)
                server.responses.append(response)  # type: ignore[attr-defined]
        finally:
            server.closed_connections += 1  # type: ignore[attr-defined]


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


@dataclass
class _RunningFixture:
    case: _Case
    server: _Server
    thread: threading.Thread

    @property
    def endpoint(self) -> ApprovedEndpoint:
        return ApprovedEndpoint("127.0.0.1", "127.0.0.1", self.server.server_address[1], "tcp", "internal")

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


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
        if len(chunk) < 1024:
            break
    return b"".join(chunks)


def _dns_query() -> bytes:
    question = b"\x03lab\x07invalid\x00\x00\x01\x00\x01"
    query = b"\xc0\x25\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    return struct.pack("!H", len(query)) + query


def _probe(endpoint: ApprovedEndpoint, service: str, *, authorized_use: bool = False) -> tuple[str, str]:
    with socket.create_connection((endpoint.resolved_ip, endpoint.port), timeout=2) as connection:
        connection.settimeout(1)
        if service == "ssh":
            raw = connection.recv(1024)
            if not raw.startswith(b"SSH-2.0-"):
                raise RuntimeError("invalid SSH identification string")
            return raw.decode("ascii", errors="replace").strip(), "SSH identification exchange"
        if service == "smtp":
            banner = connection.recv(1024)
            connection.sendall(b"EHLO loopback.invalid\r\n")
            response = _recv_all(connection)
            if not banner.startswith(b"220 ") or not response.startswith(b"250-"):
                raise RuntimeError("invalid SMTP greeting or EHLO response")
            return (banner + response).decode("ascii", errors="replace").strip(), "SMTP EHLO exchange"
        if service == "http":
            connection.sendall(b"GET /health HTTP/1.1\r\nHost: loopback.invalid\r\nConnection: close\r\n\r\n")
            raw = _recv_all(connection)
            if not raw.startswith(b"HTTP/1.1 200 OK\r\n"):
                raise RuntimeError("invalid HTTP response")
            return raw.decode("ascii", errors="replace").strip(), "HTTP GET /health response"
        if service == "docker-api":
            connection.sendall(b"GET /version HTTP/1.1\r\nHost: loopback.invalid\r\nConnection: close\r\n\r\n")
            raw = _recv_all(connection)
            if not raw.startswith(b"HTTP/1.1 200 OK\r\n") or b'"ApiVersion":"1.43"' not in raw:
                raise RuntimeError("invalid Docker Engine /version response")
            return raw.decode("ascii", errors="replace").strip(), "Docker Engine GET /version response"
        if service == "dns":
            query = _dns_query()
            connection.sendall(query)
            raw = _recv_all(connection)
            if len(raw) < 14 or raw[2:4] != query[2:4] or not (raw[4] & 0x80):
                raise RuntimeError("invalid DNS-over-TCP response")
            return raw.hex(), "DNS-over-TCP query response"
        if service == "socks":
            connection.sendall(b"\x05\x01\x00")
            raw = _recv_all(connection)
            if raw != b"\x05\x00":
                raise RuntimeError("invalid SOCKS5 method negotiation")
            return raw.hex(), "SOCKS5 method negotiation"
        if service == "redis":
            command = b"ECHO authorized-use\r\n" if authorized_use else b"PING\r\n"
            connection.sendall(command)
            raw = _recv_all(connection)
            if authorized_use and raw != b"+AUTHORIZED\r\n":
                raise RuntimeError("invalid Redis authorized-use response")
            if not authorized_use and not (raw == b"+PONG\r\n" or raw.startswith(b"-NOAUTH ")):
                raise RuntimeError("invalid Redis PING response")
            return raw.decode(
                "ascii", errors="replace"
            ).strip(), "Redis ECHO response" if authorized_use else "Redis PING response"
    raise RuntimeError(f"unsupported lab service: {service}")


class _Provider:
    def __init__(self, case: _Case) -> None:
        self.case = case

    def __call__(self, plan: ServiceValidationPlan, action: str) -> ValidationProbeOutput:
        evidence, protocol = _probe(plan.endpoint, self.case.service)
        response = evidence if action == "controlled_proof" and self.case.service == "redis" else ""
        trusted = load_trusted_issue_143_reproduction(plan.endpoint)
        return ValidationProbeOutput(
            protocol_evidence=(f"provider {protocol} sha256 {sha256(evidence.encode()).hexdigest()}",),
            dimensions={dimension: "provider supplied; independently verified below" for dimension in _DIMENSIONS},
            candidate=self.case.candidate,
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
    def __init__(self, case: _Case) -> None:
        self.case = case

    def __call__(
        self,
        plan: ServiceValidationPlan,
        selection: ValidationSelection,
        approval: AuthorizationReceipt,
        _output: ValidationProbeOutput,
    ) -> ValidationEvidenceVerification:
        evidence, protocol = _probe(plan.endpoint, self.case.service)
        effect = evidence if selection.action == "controlled_proof" and self.case.service == "redis" else ""
        authorized = ""
        if selection.action == "controlled_proof":
            authorized, _authorized_protocol = _probe(plan.endpoint, self.case.service, authorized_use=True)
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
            cleanup_evidence=("independent verifier connections closed",),
            cleanup_verified=True,
        )


class _ApprovalGate:
    def __init__(self) -> None:
        self.receipts: list[AuthorizationReceipt] = []

    def __call__(
        self, plan: ServiceValidationPlan, selection: ValidationSelection, attempt_id: str
    ) -> AuthorizationReceipt:
        receipt = AuthorizationReceipt(
            receipt_id=f"lab-approval-{attempt_id}",
            plan_id=plan.plan_id,
            endpoint=plan.endpoint,
            action=selection.action,
            attempt_id=attempt_id,
            approved=True,
        )
        self.receipts.append(receipt)
        return receipt


def _ledger(state_directory: Path) -> AssessmentBudgetLedger:
    state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_directory.chmod(0o700)
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
    return AssessmentBudgetLedger(state_directory / "service-validation.sqlite3", policy)


def _request(attempt_id: str) -> AttemptRequest:
    return AttemptRequest(attempt_id, None, 10, 100, 512)


def run_loopback_service_validation_journey(state_directory: Path | str) -> dict[str, Any]:
    """Run discovery, routing, evidence-gated validation, proof, and reporting locally."""
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

        ledger = _ledger(Path(state_directory))
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
                provider=_Provider(fixture.case),
                evidence_verifier=_Verifier(fixture.case),
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
            provider=_Provider(fixture_by_port[candidate_plan.endpoint.port].case),
            evidence_verifier=_Verifier(fixture_by_port[candidate_plan.endpoint.port].case),
            prior_result=candidate_result,
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
                "Provider and verifier use separate connections but share the lab protocol parser; parser diversity is not established.",
            ],
        }
    finally:
        for fixture in fixtures:
            fixture.stop()

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
    return report
