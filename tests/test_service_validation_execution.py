"""Loopback acceptance checks for the service-validation dispatcher boundary."""

from __future__ import annotations

import json
import secrets
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

import pytest

from cops.assessment_budget import (
    AssessmentBudgetLedger,
    AttemptRequest,
    BudgetLimits,
    BudgetPolicy,
    BudgetStoreError,
)
from cops.discovery import (
    ApprovedEndpoint,
    AuthorizationReceipt,
    ServiceValidationPlan,
    ValidationEvidenceVerification,
    ValidationProbeOutput,
    ValidationSelection,
    VersionedReproduction,
    execute_service_validation_action,
    load_trusted_issue_143_reproduction,
    service_validation_plan_digest,
)
from cops.discovery.service_validation_lab import _read_wire_request


class _LoopbackHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        with server.audit_lock:  # type: ignore[attr-defined]
            server.connection_count += 1  # type: ignore[attr-defined]
        audit_reference = ""
        pending: dict[str, object] | None = None
        request = b""
        response = b""
        try:
            self.request.sendall(server.banner)  # type: ignore[attr-defined]
            self.request.settimeout(0.5)
            audit_reference, correlation_id, request = _read_wire_request(self.request)
            with server.audit_lock:  # type: ignore[attr-defined]
                pending = server.pending_audits.pop(audit_reference, None)  # type: ignore[attr-defined]
            expected_correlation = str((pending or {}).get("dispatch_correlation_id", ""))
            if not expected_correlation or not secrets.compare_digest(correlation_id, expected_correlation):
                pending = None
                request = b""
            if request:
                server.requests.append(request)  # type: ignore[attr-defined]
            if request == b"PING\r\n" and server.proof_response:  # type: ignore[attr-defined]
                response = server.proof_response  # type: ignore[attr-defined]
                self.request.sendall(response)
                server.responses.append(response)  # type: ignore[attr-defined]
        finally:
            with server.audit_lock:  # type: ignore[attr-defined]
                server.closed_connections += 1  # type: ignore[attr-defined]
                if pending is not None:
                    server.audit[audit_reference] = {  # type: ignore[attr-defined]
                        **pending,
                        "banner": server.banner,  # type: ignore[attr-defined]
                        "request": request,
                        "response": response,
                        "closed": True,
                        "recorded_at": datetime.now(UTC).isoformat(),
                    }


class _LoopbackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, banner: bytes, proof_response: bytes = b"") -> None:
        super().__init__(("127.0.0.1", 0), _LoopbackHandler)
        self.banner = banner
        self.proof_response = proof_response
        self.connection_count = 0
        self.closed_connections = 0
        self.requests: list[bytes] = []
        self.responses: list[bytes] = []
        self.audit_lock = threading.Lock()
        self.pending_audits: dict[str, dict[str, object]] = {}
        self.audit: dict[str, dict[str, object]] = {}

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


@contextmanager
def loopback_service(banner: bytes, proof_response: bytes = b""):
    server = _LoopbackServer(banner, proof_response)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def plan_for(port: int, *, service: str = "redis", skill_id: str = "network-data-services") -> ServiceValidationPlan:
    plan = ServiceValidationPlan(
        plan_id="",
        endpoint=ApprovedEndpoint("127.0.0.1", "127.0.0.1", port, "tcp", "internal"),
        service=service,
        specialist="cops-pentest-specialist",
        skill_id=skill_id,
        session_id="session-loopback-285",
        scope_reference="scope-loopback-only",
        probe_key=f"internal:tcp:127.0.0.1:{port}",
        evidence_probe_id="discovery-probe-285",
        evidence_sha256="a" * 64,
        action="Validate the recorded service boundary",
        prerequisites=("disposable loopback fixture", "operator-selected action"),
        expected_proof="independent protocol response and five assessment dimensions",
        rollback="close the connection and stop the disposable fixture",
        stop_conditions=("endpoint identity changes", "budget or approval is absent"),
    )
    return replace(plan, plan_id=service_validation_plan_digest(plan))


def reproduction_for(endpoint: ApprovedEndpoint, *, affected_version: str = "redis-lab-5.0") -> VersionedReproduction:
    return replace(load_trusted_issue_143_reproduction(endpoint).reproduction, affected_version=affected_version)


def budget_ledger(
    tmp_path,
    *,
    engagement_id: str = "issue-285-loopback",
    db_name: str = "service-validation.sqlite3",
    clock: Callable[[], int] | None = None,
) -> AssessmentBudgetLedger:
    policy = BudgetPolicy(
        engagement_id=engagement_id,
        limits=BudgetLimits(
            max_attempts=10,
            max_estimated_tokens=1000,
            max_estimated_cost_microunits=10_000,
            max_elapsed_ms=60_000,
            max_concurrency=2,
            max_retained_output_bytes=10_000,
            max_depth=1,
            max_children_per_parent=4,
        ),
        currency="USD",
        price_source="loopback-fixture",
        price_version="1",
        price_effective_date="2026-10-14",
    )
    return AssessmentBudgetLedger(tmp_path / "private" / db_name, policy, clock=clock)


def attempt(attempt_id: str) -> AttemptRequest:
    return AttemptRequest(attempt_id, None, 10, 100, 5_000)


class ExactApprovalGate:
    def __init__(
        self,
        *,
        approved: bool = True,
        wrong_action: bool = False,
        engagement_id: str = "issue-285-loopback",
        authority_id: str = "test-operator",
        expired: bool = False,
        receipt_id: str | None = None,
    ) -> None:
        self.approved = approved
        self.wrong_action = wrong_action
        self.engagement_id = engagement_id
        self.authority_id = authority_id
        self.expired = expired
        self.receipt_id = receipt_id
        self.calls: list[tuple[str, str, str]] = []

    def __call__(
        self, plan: ServiceValidationPlan, selection: ValidationSelection, attempt_id: str
    ) -> AuthorizationReceipt:
        self.calls.append((plan.plan_id, selection.action, attempt_id))
        action = "controlled_proof" if self.wrong_action else selection.action
        now = datetime.now(UTC)
        issued_at = now - timedelta(minutes=10) if self.expired else now - timedelta(seconds=1)
        expires_at = now - timedelta(minutes=5) if self.expired else now + timedelta(minutes=5)
        return AuthorizationReceipt(
            receipt_id=self.receipt_id or f"approval-{attempt_id}",
            plan_id=plan.plan_id,
            endpoint=plan.endpoint,
            action=action,
            attempt_id=attempt_id,
            engagement_id=self.engagement_id,
            authority_id=self.authority_id,
            issued_at=issued_at.isoformat(),
            expires_at=expires_at.isoformat(),
            approved=self.approved,
        )


class SharedOneUseApprovalAuthority(ExactApprovalGate):
    """Test authority enforcing receipt uniqueness beyond one ledger database."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._issued_receipt_ids: set[str] = set()

    def __call__(
        self, plan: ServiceValidationPlan, selection: ValidationSelection, attempt_id: str
    ) -> AuthorizationReceipt:
        receipt = super().__call__(plan, selection, attempt_id)
        if receipt.receipt_id in self._issued_receipt_ids:
            raise RuntimeError("approval receipt was already issued by this authority")
        self._issued_receipt_ids.add(receipt.receipt_id)
        return receipt


class LoopbackProvider:
    """Native fixture provider; its evidence fields remain untrusted input."""

    def __init__(
        self,
        server: _LoopbackServer,
        *,
        force_candidate: bool = False,
        wrong_reproduction_endpoint: bool = False,
        wrong_reproduction_version: bool = False,
    ) -> None:
        self.server = server
        self.force_candidate = force_candidate
        self.wrong_reproduction_endpoint = wrong_reproduction_endpoint
        self.wrong_reproduction_version = wrong_reproduction_version
        self.calls: list[tuple[ApprovedEndpoint, str]] = []

    def __call__(self, plan: ServiceValidationPlan, action: str, context) -> ValidationProbeOutput:
        self.calls.append((plan.endpoint, action))
        request = b"PING\r\n" if action == "controlled_proof" else b""
        protocol = "Redis controlled proof" if action == "controlled_proof" else "passive banner"
        audit_reference = self.server.issue_audit_reference(
            {
                "plan_id": plan.plan_id,
                "attempt_id": context.attempt_id,
                "approval_receipt_id": context.approval_receipt_id,
                "action": action,
                "endpoint": asdict(plan.endpoint),
                "dispatch_correlation_id": context.correlation_id,
                "service": plan.service,
                "protocol": protocol,
                "expected_request": request,
            }
        )
        try:
            with socket.create_connection((plan.endpoint.resolved_ip, plan.endpoint.port), timeout=2) as connection:
                banner = connection.recv(512).decode("utf-8", errors="replace").strip()
                frame = (
                    b"COPS-AUDIT "
                    + audit_reference.encode("ascii")
                    + b" "
                    + context.correlation_id.encode("ascii")
                    + b" "
                    + str(len(request)).encode("ascii")
                    + b"\n"
                    + request
                )
                connection.sendall(frame)
                connection.shutdown(socket.SHUT_WR)
                proof_chunks: list[bytes] = []
                while chunk := connection.recv(64):
                    proof_chunks.append(chunk)
                proof = b"".join(proof_chunks).decode("utf-8", errors="replace").strip()
        except Exception:
            self.server.discard_pending_audit(audit_reference)
            raise

        affected = banner.startswith("-ERR Redis 5.0")
        candidate = affected or self.force_candidate
        reproduction_endpoint = plan.endpoint
        if self.wrong_reproduction_endpoint:
            reproduction_endpoint = ApprovedEndpoint(
                plan.endpoint.host,
                plan.endpoint.resolved_ip,
                plan.endpoint.port + 1,
                plan.endpoint.transport,
                plan.endpoint.vantage,
            )
        return ValidationProbeOutput(
            protocol_evidence=("provider claims any protocol",),
            dimensions={
                dimension: "provider claims tested"
                for dimension in ("exposure", "authentication", "configuration", "version", "trust")
            },
            candidate=candidate,
            effect_evidence=(f"provider claims PING response: {proof or '+PONG'}",),
            proof_succeeded=True,
            cleanup_evidence=("provider claims cleanup",),
            reproduction=(
                reproduction_for(
                    reproduction_endpoint,
                    affected_version="redis-lab-4.0" if self.wrong_reproduction_version else "redis-lab-5.0",
                )
                if candidate
                else None
            ),
            finding=load_trusted_issue_143_reproduction(plan.endpoint).finding if candidate else None,
            tokens=3,
            cost_microunits=30,
            retained_output_bytes=5_000,
            audit_reference=audit_reference,
        )


class LoopbackEvidenceVerifier:
    """Correlates fixture-side passive audit records with provider output."""

    def __init__(
        self,
        server: _LoopbackServer,
        *,
        incomplete: bool = False,
        authorized_use: bool = False,
        wrong_receipt: bool = False,
        wrong_plan: bool = False,
        wrong_attempt: bool = False,
        wrong_evidence_digest: bool = False,
        stale_verified_at: bool = False,
        malformed_verified_at: bool = False,
        stale_audit_recorded_at: bool = False,
        malformed_audit_recorded_at: bool = False,
        wrong_reproduction_digest: bool = False,
    ) -> None:
        self.server = server
        self.incomplete = incomplete
        self.authorized_use = authorized_use
        self.wrong_receipt = wrong_receipt
        self.wrong_plan = wrong_plan
        self.wrong_attempt = wrong_attempt
        self.wrong_evidence_digest = wrong_evidence_digest
        self.stale_verified_at = stale_verified_at
        self.malformed_verified_at = malformed_verified_at
        self.stale_audit_recorded_at = stale_audit_recorded_at
        self.malformed_audit_recorded_at = malformed_audit_recorded_at
        self.wrong_reproduction_digest = wrong_reproduction_digest
        self.calls = 0

    def __call__(self, plan, selection, approval, output, context) -> ValidationEvidenceVerification:
        self.calls += 1
        deadline = time.monotonic() + 0.5
        audit = None
        while time.monotonic() < deadline:
            with self.server.audit_lock:
                audit = self.server.audit.pop(output.audit_reference, None)
            if audit is not None:
                break
            time.sleep(0.005)
        if audit is None:
            raise RuntimeError("fixture passive audit record was unavailable")

        expected_request = b"PING\r\n" if selection.action == "controlled_proof" else b""
        expected_protocol = "Redis controlled proof" if selection.action == "controlled_proof" else "passive banner"
        expected_metadata = {
            "plan_id": plan.plan_id,
            "attempt_id": approval.attempt_id,
            "approval_receipt_id": approval.receipt_id,
            "action": selection.action,
            "endpoint": asdict(plan.endpoint),
            "dispatch_correlation_id": context.correlation_id,
            "service": plan.service,
            "protocol": expected_protocol,
            "expected_request": expected_request,
        }
        if any(audit.get(key) != value for key, value in expected_metadata.items()):
            raise RuntimeError("fixture passive audit record did not match the exact dispatch")
        if audit.get("request") != expected_request or audit.get("closed") is not True:
            raise RuntimeError("fixture passive audit request or close evidence did not match")

        banner = bytes(audit["banner"]).decode("utf-8", errors="replace").strip()

        if self.incomplete:
            return ValidationEvidenceVerification(
                approval_receipt_id=approval.receipt_id,
                plan_id=plan.plan_id,
                attempt_id=approval.attempt_id,
                evidence_sha256=plan.evidence_sha256,
                endpoint=plan.endpoint,
                action=selection.action,
                observed_version="",
                protocol_evidence=(),
                dimensions={},
                verified_at=datetime.now(UTC).isoformat(),
                audit_recorded_at=str(audit["recorded_at"]),
                audit_reference=output.audit_reference,
                dispatch_correlation_id=context.correlation_id,
            )

        protected = "authentication required" in banner
        affected = banner.startswith("-ERR Redis 5.0 no password configured")
        version = "redis-lab-7.2-protected" if protected else ("redis-lab-5.0" if affected else "ssh-lab-9.0")
        proof_seen = audit["request"] == b"PING\r\n" and audit["response"] == b"+PONG\r\n"
        cleanup_seen = audit["closed"] is True
        return ValidationEvidenceVerification(
            approval_receipt_id="wrong-receipt" if self.wrong_receipt else approval.receipt_id,
            plan_id="wrong-plan" if self.wrong_plan else plan.plan_id,
            attempt_id="wrong-attempt" if self.wrong_attempt else approval.attempt_id,
            evidence_sha256="b" * 64 if self.wrong_evidence_digest else plan.evidence_sha256,
            endpoint=plan.endpoint,
            action=selection.action,
            observed_version=version,
            protocol_evidence=(f"passive fixture audit response: {banner}",),
            dimensions={
                "exposure": "exact approved loopback endpoint responded",
                "authentication": "required" if protected else "not required by the observed response",
                "configuration": "protected fixture" if protected else "disposable loopback fixture",
                "version": version,
                "trust": "untrusted client at the approved loopback boundary",
            },
            verified_at=(
                "not-a-time"
                if self.malformed_verified_at
                else (
                    datetime.now(UTC) - timedelta(hours=1) if self.stale_verified_at else datetime.now(UTC)
                ).isoformat()
            ),
            audit_recorded_at=(
                "not-a-time"
                if self.malformed_audit_recorded_at
                else (
                    (datetime.now(UTC) - timedelta(hours=1)).isoformat()
                    if self.stale_audit_recorded_at
                    else str(audit["recorded_at"])
                )
            ),
            reproduction_sha256=(
                "b" * 64
                if self.wrong_reproduction_digest
                else load_trusted_issue_143_reproduction(plan.endpoint).sha256
            ),
            candidate_verified=affected,
            finding_effect="+PONG" if proof_seen else "",
            effect_evidence=("fixture audit recorded PING and returned +PONG",) if proof_seen else (),
            finding_effect_verified=proof_seen,
            authorized_use_evidence=("approval-bound PING completed at the exact endpoint",)
            if proof_seen and self.authorized_use
            else (),
            authorized_use_verified=proof_seen and self.authorized_use,
            cleanup_evidence=("fixture audit recorded all opened connections closed",) if cleanup_seen else (),
            cleanup_verified=cleanup_seen,
            audit_reference=output.audit_reference,
            dispatch_correlation_id=context.correlation_id,
        )


@pytest.mark.parametrize(
    ("banner", "expected_auth"),
    (
        (b"SSH-2.0-Lab_9.0\r\n", "not required by the observed response"),
        (b"-ERR Redis 7.2 authentication required; remediated\r\n", "required"),
    ),
)
def test_real_loopback_boundary_records_benign_and_protected_nonfindings(tmp_path, banner, expected_auth):
    with loopback_service(banner) as server:
        service = "ssh" if banner.startswith(b"SSH") else "redis"
        skill = "network-remote-and-file-services" if service == "ssh" else "network-data-services"
        plan = plan_for(server.server_address[1], service=service, skill_id=skill)
        provider = LoopbackProvider(server)
        verifier = LoopbackEvidenceVerifier(server)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=budget_ledger(tmp_path),
            request=attempt(f"{service}-low-impact"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=verifier,
        )

    assert result.status == "completed"
    assert result.observed_exposure
    assert result.dimensions["authentication"] == expected_auth
    assert not result.candidate and not result.verified_finding and not result.successful_authorized_use
    assert result.protocol_evidence[0].startswith("passive fixture audit response:")
    assert provider.calls == [(plan.endpoint, "low_impact_validation")]
    assert verifier.calls == 1
    assert server.connection_count == 1


def _run_candidate(plan, server, tmp_path, ledger=None):
    active_ledger = ledger or budget_ledger(tmp_path)
    provider = LoopbackProvider(server)
    result = execute_service_validation_action(
        plan,
        ValidationSelection(plan.plan_id, "low_impact_validation"),
        ledger=active_ledger,
        request=attempt("redis-observe"),
        authorization_gate=ExactApprovalGate(),
        provider=provider,
        evidence_verifier=LoopbackEvidenceVerifier(server),
    )
    return result, provider, active_ledger


def test_verified_finding_does_not_imply_successful_authorized_use(tmp_path):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n", b"+PONG\r\n") as server:
        plan = plan_for(server.server_address[1])
        low_impact, provider, ledger = _run_candidate(plan, server, tmp_path)
        proof = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "controlled_proof"),
            ledger=ledger,
            request=attempt("redis-proof"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=LoopbackEvidenceVerifier(server),
            prerequisite_receipt=low_impact.prerequisite_receipt,
        )

    assert low_impact.status == "completed" and low_impact.candidate
    assert low_impact.observed_version == "redis-lab-5.0"
    assert low_impact.reproduction_expected_proof == "+PONG"
    assert proof.status == "completed" and proof.verified_finding
    assert not proof.successful_authorized_use
    assert proof.effect_evidence == ("fixture audit recorded PING and returned +PONG",)
    assert proof.authorized_use_evidence == ()
    assert proof.cleanup_evidence and proof.finding_id == "COPS-LAB-143"
    assert proof.action == "controlled_proof"
    assert proof.approval_receipt_id == "approval-redis-proof"
    finding = load_trusted_issue_143_reproduction(plan.endpoint).finding
    assert all(
        proof.coverage[f"finding_{field}"] == "documented"
        for field in finding.__dataclass_fields__
        if field != "finding_id"
    )
    assert {mapping.technique_id for mapping in proof.attack_mappings} == {"T1046", "T1210"}
    assert all(mapping.evidence_limit for mapping in proof.attack_mappings)


def test_successful_authorized_use_requires_distinct_effect_evidence(tmp_path):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n", b"+PONG\r\n") as server:
        plan = plan_for(server.server_address[1])
        low_impact, provider, ledger = _run_candidate(plan, server, tmp_path)
        proof = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "controlled_proof"),
            ledger=ledger,
            request=attempt("redis-authorized-use"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=LoopbackEvidenceVerifier(server, authorized_use=True),
            prerequisite_receipt=low_impact.prerequisite_receipt,
        )

    assert proof.verified_finding and proof.successful_authorized_use
    assert proof.authorized_use_evidence == ("approval-bound PING completed at the exact endpoint",)
    assert proof.authorized_use_evidence != proof.effect_evidence


def test_fabricated_provider_claims_cannot_override_fixture_audit_evidence(tmp_path):
    with loopback_service(b"-ERR Redis 7.2 authentication required; remediated\r\n") as server:
        plan = plan_for(server.server_address[1])
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=budget_ledger(tmp_path),
            request=attempt("fabricated-provider"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server, force_candidate=True),
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "insufficient_evidence"
    assert result.observed_version == "redis-lab-7.2-protected"
    assert result.dimensions["authentication"] == "required"
    assert not result.candidate and result.reproduction_reference is None and not result.verified_finding


def test_issue_143_reproduction_must_bind_exact_endpoint(tmp_path):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n") as server:
        plan = plan_for(server.server_address[1])
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=budget_ledger(tmp_path),
            request=attempt("wrong-reproduction-endpoint"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server, wrong_reproduction_endpoint=True),
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "insufficient_evidence" and result.observed_exposure
    assert not result.candidate and result.coverage["reproduction"] == "unverified"


def test_issue_143_reproduction_must_bind_exact_observed_version(tmp_path):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n") as server:
        plan = plan_for(server.server_address[1])
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=budget_ledger(tmp_path),
            request=attempt("wrong-reproduction-version"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server, wrong_reproduction_version=True),
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "insufficient_evidence" and result.observed_version == "redis-lab-5.0"
    assert not result.candidate and result.reproduction_reference is None


def test_controlled_proof_requires_exact_passively_observed_effect(tmp_path):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n", b"+NOPE\r\n") as server:
        plan = plan_for(server.server_address[1])
        low_impact, provider, ledger = _run_candidate(plan, server, tmp_path)
        proof = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "controlled_proof"),
            ledger=ledger,
            request=attempt("mismatched-proof-effect"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=LoopbackEvidenceVerifier(server, authorized_use=True),
            prerequisite_receipt=low_impact.prerequisite_receipt,
        )

    assert low_impact.candidate
    assert proof.status == "insufficient_evidence"
    assert not proof.verified_finding and not proof.successful_authorized_use
    assert proof.effect_evidence == () and proof.authorized_use_evidence == ()


def test_missing_fixture_audit_evidence_is_insufficient_even_with_provider_claims(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=budget_ledger(tmp_path),
            request=attempt("incomplete"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=LoopbackEvidenceVerifier(server, incomplete=True),
        )

    assert result.status == "insufficient_evidence"
    assert not result.observed_exposure and result.protocol_evidence == ()
    assert not result.candidate and not result.verified_finding and not result.successful_authorized_use


@pytest.mark.parametrize(
    "mismatch",
    (
        "wrong_receipt",
        "wrong_plan",
        "wrong_attempt",
        "wrong_evidence_digest",
        "stale_verified_at",
        "malformed_verified_at",
        "stale_audit_recorded_at",
        "malformed_audit_recorded_at",
    ),
)
def test_mismatched_passive_verification_binding_is_dispatch_uncertain(tmp_path, mismatch):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        provider = LoopbackProvider(server)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt(f"wrong-verification-{mismatch}"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=LoopbackEvidenceVerifier(server, **{mismatch: True}),
        )
        replay_gate = ExactApprovalGate()
        replay = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt(f"wrong-verification-{mismatch}"),
            authorization_gate=replay_gate,
            provider=provider,
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "dispatch_uncertain" and result.protocol_evidence == ()
    assert not result.observed_exposure
    assert ledger.get_attempt(f"wrong-verification-{mismatch}").state == "uncertain"
    assert ledger.snapshot().active_concurrency == 1
    assert replay.status == "budget_denied"
    assert replay_gate.calls == [] and len(provider.calls) == 1


def test_issue_143_reproduction_requires_trusted_digest(tmp_path):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n") as server:
        plan = plan_for(server.server_address[1])
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=budget_ledger(tmp_path),
            request=attempt("wrong-reproduction-digest"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=LoopbackEvidenceVerifier(server, wrong_reproduction_digest=True),
        )

    assert result.status == "insufficient_evidence" and result.observed_exposure
    assert not result.candidate
    assert result.coverage["reproduction"] == "unverified"
    assert result.reproduction_reference is None
    assert result.reproduction_sha256 is None


def test_provider_unavailable_fails_before_budget_or_approval(tmp_path):
    plan = plan_for(65530)
    ledger = budget_ledger(tmp_path)
    gate = ExactApprovalGate()
    result = execute_service_validation_action(
        plan,
        ValidationSelection(plan.plan_id, "low_impact_validation"),
        ledger=ledger,
        request=attempt("no-provider"),
        authorization_gate=gate,
        provider=None,
        evidence_verifier=None,
    )

    assert result.status == "provider_unavailable"
    assert ledger.snapshot().charged_attempts == 0 and gate.calls == []


def test_wrong_approval_and_reused_attempt_fail_before_provider_dispatch(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        provider = LoopbackProvider(server)
        verifier = LoopbackEvidenceVerifier(server)
        denied = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("wrong-approval"),
            authorization_gate=ExactApprovalGate(wrong_action=True),
            provider=provider,
            evidence_verifier=verifier,
        )
        completed = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("one-use-attempt"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=verifier,
        )
        replay_gate = ExactApprovalGate()
        replay = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("one-use-attempt"),
            authorization_gate=replay_gate,
            provider=provider,
            evidence_verifier=verifier,
        )

    assert denied.status == "authorization_denied"
    assert completed.status == "completed" and replay.status == "budget_denied"
    assert completed.action == "low_impact_validation"
    assert completed.approval_receipt_id == "approval-one-use-attempt"
    assert len(provider.calls) == 1 and verifier.calls == 1
    assert replay_gate.calls == [] and server.connection_count == 1


@pytest.mark.parametrize("field", ["receipt_id", "authority_id"])
def test_oversized_approval_identity_fails_before_provider_dispatch(tmp_path, field):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        provider = LoopbackProvider(server)
        gate = ExactApprovalGate(**{field: "x" * 4097})
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt(f"oversized-{field}"),
            authorization_gate=gate,
            provider=provider,
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "authorization_denied"
    assert provider.calls == [] and server.connection_count == 0
    assert ledger.get_attempt(f"oversized-{field}").state == "released"


def test_authority_rejects_receipt_replay_across_fresh_ledgers(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        authority = SharedOneUseApprovalAuthority(receipt_id="shared-approval")
        provider = LoopbackProvider(server)
        verifier = LoopbackEvidenceVerifier(server)
        first = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=budget_ledger(tmp_path, db_name="first.sqlite3"),
            request=attempt("same-attempt"),
            authorization_gate=authority,
            provider=provider,
            evidence_verifier=verifier,
        )
        second_ledger = budget_ledger(tmp_path, db_name="second.sqlite3")
        replay = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=second_ledger,
            request=attempt("same-attempt"),
            authorization_gate=authority,
            provider=provider,
            evidence_verifier=verifier,
        )

    assert first.status == "completed"
    assert replay.status == "authorization_error"
    assert second_ledger.get_attempt("same-attempt").state == "released"
    assert len(provider.calls) == 1 and server.connection_count == 1


def test_authorization_exception_releases_undispatched_reservation(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        provider = LoopbackProvider(server)
        verifier = LoopbackEvidenceVerifier(server)

        def failing_authorization_gate(_plan, _selection, _attempt_id):
            raise RuntimeError("authorization service unavailable")

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("authorization-exception"),
            authorization_gate=failing_authorization_gate,
            provider=provider,
            evidence_verifier=verifier,
        )

    snapshot = ledger.snapshot()
    assert result.status == "authorization_error"
    assert ledger.get_attempt("authorization-exception").state == "released"
    assert snapshot.charged_attempts == 0 and snapshot.active_concurrency == 0
    assert provider.calls == [] and verifier.calls == 0
    assert server.connection_count == 0


def test_authorization_interrupt_releases_undispatched_reservation(tmp_path):
    plan = plan_for(22, service="ssh", skill_id="network-remote-and-file-services")
    ledger = budget_ledger(tmp_path)

    def interrupted_authorization_gate(_plan, _selection, _attempt_id):
        raise KeyboardInterrupt

    def unused_execution_boundary(*_args):
        raise AssertionError("authorization interruption must prevent dispatch")

    with pytest.raises(KeyboardInterrupt):
        execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("authorization-interrupt"),
            authorization_gate=interrupted_authorization_gate,
            provider=unused_execution_boundary,
            evidence_verifier=unused_execution_boundary,
        )

    snapshot = ledger.snapshot()
    assert ledger.get_attempt("authorization-interrupt").state == "released"
    assert snapshot.charged_attempts == 0 and snapshot.active_concurrency == 0


def test_dispatch_intent_failure_releases_undispatched_reservation(tmp_path, monkeypatch):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        provider = LoopbackProvider(server)
        verifier = LoopbackEvidenceVerifier(server)

        def failing_mark_dispatched(_attempt_id, **_kwargs):
            raise RuntimeError("dispatch ledger unavailable")

        monkeypatch.setattr(ledger, "mark_dispatched", failing_mark_dispatched)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("dispatch-intent-failure"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=verifier,
        )

    snapshot = ledger.snapshot()
    assert result.status == "dispatch_error"
    assert ledger.get_attempt("dispatch-intent-failure").state == "released"
    assert snapshot.charged_attempts == 0 and snapshot.active_concurrency == 0
    assert provider.calls == [] and verifier.calls == 0
    assert server.connection_count == 0


def test_provider_exception_after_dispatch_marks_usage_uncertain(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        verifier = LoopbackEvidenceVerifier(server)

        def failing_provider(_plan, _action, _context):
            raise RuntimeError("provider connection outcome unknown")

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("provider-exception"),
            authorization_gate=ExactApprovalGate(),
            provider=failing_provider,
            evidence_verifier=verifier,
        )

    snapshot = ledger.snapshot()
    assert result.status == "dispatch_uncertain"
    assert ledger.get_attempt("provider-exception").state == "uncertain"
    assert snapshot.charged_attempts == 1 and snapshot.active_concurrency == 1
    assert verifier.calls == 0
    assert server.connection_count == 0


@pytest.mark.parametrize("malformed_source", ("provider", "verifier"))
def test_invalid_unicode_after_dispatch_marks_usage_uncertain(tmp_path, malformed_source):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        fixture_provider = LoopbackProvider(server)
        fixture_verifier = LoopbackEvidenceVerifier(server)

        def provider(*args):
            output = fixture_provider(*args)
            return replace(output, protocol_evidence=("\ud800",)) if malformed_source == "provider" else output

        def verifier(*args):
            evidence = fixture_verifier(*args)
            return replace(evidence, protocol_evidence=("\ud800",)) if malformed_source == "verifier" else evidence

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt(f"invalid-unicode-{malformed_source}"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=verifier,
        )

    assert result.status == "dispatch_uncertain"
    assert ledger.get_attempt(f"invalid-unicode-{malformed_source}").state == "uncertain"
    assert len(fixture_provider.calls) == 1
    assert fixture_verifier.calls == (0 if malformed_source == "provider" else 1)


def test_postcommit_reconciliation_error_recovers_exact_completed_result(tmp_path, monkeypatch):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n") as server:
        plan = plan_for(server.server_address[1])
        ledger = budget_ledger(tmp_path)
        original_reconcile = ledger.reconcile

        def commit_then_raise(receipt, **kwargs):
            original_reconcile(receipt, **kwargs)
            raise BudgetStoreError("lost commit acknowledgement")

        monkeypatch.setattr(ledger, "reconcile", commit_then_raise)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("postcommit-reconcile"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "completed"
    assert result.prerequisite_receipt is not None
    assert ledger.get_attempt("postcommit-reconcile").state == "settled"


def test_postcommit_recovery_rejects_concurrently_consumed_prerequisite(tmp_path, monkeypatch):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n") as server:
        plan = plan_for(server.server_address[1])
        ledger = budget_ledger(tmp_path)
        original_reconcile = ledger.reconcile

        def commit_consume_then_raise(receipt, **kwargs):
            original_reconcile(receipt, **kwargs)
            ledger.reserve(attempt("concurrent-prerequisite-consumer"))
            ledger.mark_dispatched(
                "concurrent-prerequisite-consumer",
                prerequisite_receipt_id=kwargs["validation_prerequisite_id"],
                expected_prerequisite=kwargs["validation_prerequisite"],
            )
            raise BudgetStoreError("lost commit acknowledgement")

        monkeypatch.setattr(ledger, "reconcile", commit_consume_then_raise)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("postcommit-consumed-prerequisite"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "dispatch_uncertain"
    assert result.prerequisite_receipt is None
    assert ledger.get_attempt("postcommit-consumed-prerequisite").state == "settled"
    assert ledger.get_attempt("concurrent-prerequisite-consumer").state == "dispatched"


def test_postcommit_reconciliation_error_recovers_exact_failed_result(tmp_path, monkeypatch):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        original_reconcile = ledger.reconcile

        def commit_then_raise(receipt, **kwargs):
            original_reconcile(receipt, **kwargs)
            raise BudgetStoreError("lost commit acknowledgement")

        monkeypatch.setattr(ledger, "reconcile", commit_then_raise)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("postcommit-failed-reconcile"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=LoopbackEvidenceVerifier(server, incomplete=True),
        )

    assert result.status == "insufficient_evidence"
    assert result.prerequisite_receipt is None
    assert ledger.get_attempt("postcommit-failed-reconcile").state == "settled"


def test_precommit_reconciliation_error_marks_result_uncertain(tmp_path, monkeypatch):
    with loopback_service(b"-ERR Redis 5.0 no password configured\r\n") as server:
        plan = plan_for(server.server_address[1])
        ledger = budget_ledger(tmp_path)

        def fail_before_commit(*_args, **_kwargs):
            raise BudgetStoreError("commit unavailable")

        monkeypatch.setattr(ledger, "reconcile", fail_before_commit)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("precommit-reconcile"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "dispatch_uncertain"
    assert ledger.get_attempt("precommit-reconcile").state == "uncertain"


def test_audit_published_during_verification_is_accepted(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        delegate = LoopbackEvidenceVerifier(server)

        def verifier(*args):
            verification = delegate(*args)
            audit_recorded_at = datetime.now(UTC)
            verified_at = datetime.now(UTC)
            return replace(
                verification,
                audit_recorded_at=audit_recorded_at.isoformat(),
                verified_at=verified_at.isoformat(),
            )

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("audit-during-verification"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=verifier,
        )

    assert result.status == "completed"
    assert ledger.get_attempt("audit-during-verification").state == "settled"


def test_independently_verified_low_impact_effect_marks_dispatch_uncertain(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        delegate = LoopbackEvidenceVerifier(server)

        def verifier(*args):
            verification = delegate(*args)
            return replace(
                verification,
                finding_effect="unexpected verified effect",
                effect_evidence=("fixture audit independently recorded an unexpected effect",),
                finding_effect_verified=True,
            )

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("unexpected-low-impact-effect"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=verifier,
        )

    assert result.status == "dispatch_uncertain"
    assert result.reason == "the low-impact action produced an independently verified effect"
    assert result.effect_evidence == ("fixture audit independently recorded an unexpected effect",)
    assert ledger.get_attempt("unexpected-low-impact-effect").state == "uncertain"


@pytest.mark.parametrize(
    ("finding_effect_verified", "finding_effect", "effect_evidence"),
    (
        (False, "unverified effect", ("unverified effect evidence",)),
        (True, "verified effect", ()),
    ),
    ids=("evidence-with-false-flag", "true-flag-without-evidence"),
)
def test_contradictory_finding_effect_verification_is_rejected(
    tmp_path,
    finding_effect_verified,
    finding_effect,
    effect_evidence,
):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        delegate = LoopbackEvidenceVerifier(server)

        def verifier(*args):
            return replace(
                delegate(*args),
                finding_effect=finding_effect,
                effect_evidence=effect_evidence,
                finding_effect_verified=finding_effect_verified,
            )

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt(f"contradictory-effect-{finding_effect_verified}"),
            authorization_gate=ExactApprovalGate(),
            provider=LoopbackProvider(server),
            evidence_verifier=verifier,
        )

    assert result.status == "dispatch_uncertain"
    assert result.reason == "passive evidence could not be bound to the dispatched action: malformed evidence fields"
    assert ledger.get_attempt(f"contradictory-effect-{finding_effect_verified}").state == "uncertain"


def test_approval_expiring_before_durable_dispatch_is_rejected_atomically(tmp_path, monkeypatch):
    ledger_now = [time.time_ns() // 1_000_000]
    ledger = budget_ledger(tmp_path, clock=lambda: ledger_now[0])
    original_mark_dispatched = ledger.mark_dispatched
    original_transaction = ledger._transaction
    delay_next_transaction = False
    approval_expires_at_ms = 0
    provider_calls = 0

    @contextmanager
    def delayed_transaction():
        nonlocal delay_next_transaction
        if delay_next_transaction:
            delay_next_transaction = False
            ledger_now[0] = approval_expires_at_ms
        with original_transaction() as db:
            yield db

    def delayed_mark_dispatched(*args, **kwargs):
        nonlocal delay_next_transaction, approval_expires_at_ms
        expires_at = datetime.fromisoformat(
            str(kwargs["dispatch_intent"]["approval_expires_at"]).replace("Z", "+00:00")
        )
        approval_expires_at_ms = int(expires_at.timestamp() * 1000)
        delay_next_transaction = True
        return original_mark_dispatched(*args, **kwargs)

    def provider(*_args):
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("provider must not run after approval expiry")

    monkeypatch.setattr(ledger, "mark_dispatched", delayed_mark_dispatched)
    monkeypatch.setattr(ledger, "_transaction", delayed_transaction)
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("approval-expires-during-dispatch"),
            authorization_gate=ExactApprovalGate(),
            provider=provider,
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "dispatch_error"
    assert provider_calls == 0
    assert ledger.get_attempt("approval-expires-during-dispatch").state == "released"
    assert ledger.snapshot().charged_attempts == 0
    assert ledger.snapshot().active_concurrency == 0


def test_maximum_length_attempt_id_produces_bounded_receipt(tmp_path, monkeypatch):
    attempt_id = "a" * 128
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        receipts = []
        original_reconcile = ledger.reconcile

        def capture_receipt(receipt, **kwargs):
            receipts.append(receipt)
            return original_reconcile(receipt, **kwargs)

        monkeypatch.setattr(ledger, "reconcile", capture_receipt)
        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt(attempt_id),
            authorization_gate=ExactApprovalGate(receipt_id="approval-max-attempt"),
            provider=LoopbackProvider(server),
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "completed"
    assert len(receipts) == 1
    assert len(receipts[0].receipt_id) <= 128
    expected_retained_output_bytes = len(
        json.dumps(asdict(result), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    assert receipts[0].retained_output_bytes == expected_retained_output_bytes
    assert receipts[0].retained_output_bytes < 5_000
    assert ledger.get_attempt(attempt_id).state == "settled"


def test_provider_retained_output_declaration_is_an_upper_bound(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        provider = LoopbackProvider(server)

        def underreporting_provider(*args):
            return replace(provider(*args), retained_output_bytes=1)

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("underreported-retained-output"),
            authorization_gate=ExactApprovalGate(),
            provider=underreporting_provider,
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "dispatch_uncertain"
    assert result.reason == "retained result exceeded its declared or reserved output bound"
    assert ledger.get_attempt("underreported-retained-output").state == "uncertain"


@pytest.mark.parametrize(
    "protocol_evidence",
    [
        ("x" * 4097,),
        tuple(f"evidence-{index}" for index in range(33)),
    ],
    ids=("oversized-field", "excessive-item-count"),
)
def test_provider_retained_evidence_is_bounded(tmp_path, protocol_evidence):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        provider = LoopbackProvider(server)

        def oversized_provider(*args):
            return replace(provider(*args), protocol_evidence=protocol_evidence)

        result = execute_service_validation_action(
            plan,
            ValidationSelection(plan.plan_id, "low_impact_validation"),
            ledger=ledger,
            request=attempt("bounded-retained-evidence"),
            authorization_gate=ExactApprovalGate(),
            provider=oversized_provider,
            evidence_verifier=LoopbackEvidenceVerifier(server),
        )

    assert result.status == "dispatch_uncertain"
    assert result.reason == "provider returned malformed or unbounded usage evidence"
    assert ledger.get_attempt("bounded-retained-evidence").state == "uncertain"


def test_provider_interrupt_after_dispatch_marks_usage_uncertain(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        verifier = LoopbackEvidenceVerifier(server)

        def interrupted_provider(_plan, _action, _context):
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            execute_service_validation_action(
                plan,
                ValidationSelection(plan.plan_id, "low_impact_validation"),
                ledger=ledger,
                request=attempt("provider-interrupt"),
                authorization_gate=ExactApprovalGate(),
                provider=interrupted_provider,
                evidence_verifier=verifier,
            )

    assert ledger.get_attempt("provider-interrupt").state == "uncertain"
    assert ledger.snapshot().active_concurrency == 1
    assert verifier.calls == 0


def test_provider_base_exception_after_dispatch_marks_usage_uncertain(tmp_path):
    class ProviderAbort(BaseException):
        pass

    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        verifier = LoopbackEvidenceVerifier(server)

        def aborted_provider(_plan, _action, _context):
            raise ProviderAbort

        with pytest.raises(ProviderAbort):
            execute_service_validation_action(
                plan,
                ValidationSelection(plan.plan_id, "low_impact_validation"),
                ledger=ledger,
                request=attempt("provider-base-exception"),
                authorization_gate=ExactApprovalGate(),
                provider=aborted_provider,
                evidence_verifier=verifier,
            )

    assert ledger.get_attempt("provider-base-exception").state == "uncertain"
    assert ledger.snapshot().active_concurrency == 1
    assert verifier.calls == 0


def test_verifier_interrupt_after_dispatch_marks_usage_uncertain(tmp_path):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)

        def interrupted_verifier(*_args):
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            execute_service_validation_action(
                plan,
                ValidationSelection(plan.plan_id, "low_impact_validation"),
                ledger=ledger,
                request=attempt("verifier-interrupt"),
                authorization_gate=ExactApprovalGate(),
                provider=LoopbackProvider(server),
                evidence_verifier=interrupted_verifier,
            )

    assert ledger.get_attempt("verifier-interrupt").state == "uncertain"
    assert ledger.snapshot().active_concurrency == 1


def test_precommit_reconciliation_interrupt_marks_usage_uncertain(tmp_path, monkeypatch):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)

        def interrupted_reconcile(*_args, **_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(ledger, "reconcile", interrupted_reconcile)
        with pytest.raises(KeyboardInterrupt):
            execute_service_validation_action(
                plan,
                ValidationSelection(plan.plan_id, "low_impact_validation"),
                ledger=ledger,
                request=attempt("precommit-interrupt"),
                authorization_gate=ExactApprovalGate(),
                provider=LoopbackProvider(server),
                evidence_verifier=LoopbackEvidenceVerifier(server),
            )

    assert ledger.get_attempt("precommit-interrupt").state == "uncertain"


def test_postcommit_reconciliation_interrupt_preserves_settlement(tmp_path, monkeypatch):
    with loopback_service(b"SSH-2.0-Lab_9.0\r\n") as server:
        plan = plan_for(server.server_address[1], service="ssh", skill_id="network-remote-and-file-services")
        ledger = budget_ledger(tmp_path)
        original_reconcile = ledger.reconcile

        def commit_then_interrupt(receipt, **kwargs):
            original_reconcile(receipt, **kwargs)
            raise KeyboardInterrupt

        monkeypatch.setattr(ledger, "reconcile", commit_then_interrupt)
        with pytest.raises(KeyboardInterrupt):
            execute_service_validation_action(
                plan,
                ValidationSelection(plan.plan_id, "low_impact_validation"),
                ledger=ledger,
                request=attempt("postcommit-interrupt"),
                authorization_gate=ExactApprovalGate(),
                provider=LoopbackProvider(server),
                evidence_verifier=LoopbackEvidenceVerifier(server),
            )

    assert ledger.get_attempt("postcommit-interrupt").state == "settled"
