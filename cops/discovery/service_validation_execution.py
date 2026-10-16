"""Budgeted dispatcher boundary for operator-selected service validation.

Providers are injected adapters.  This coordinator does not infer permission,
select an action, or convert a port observation into a finding.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256

from cops.assessment_budget import AssessmentBudgetLedger, AttemptRequest, BudgetDenied, Receipt

from .service_entry_validation import (
    ApprovedEndpoint,
    ServiceValidationPlan,
    service_validation_plan_digest,
    service_validation_plan_is_intact,
)

_ACTIONS = frozenset({"low_impact_validation", "controlled_proof"})
_DIMENSIONS = ("exposure", "authentication", "configuration", "version", "trust")


@dataclass(frozen=True)
class ValidationSelection:
    plan_id: str
    action: str

    def __post_init__(self) -> None:
        if not self.plan_id or self.action not in _ACTIONS:
            raise ValueError("invalid validation selection")


@dataclass(frozen=True)
class AuthorizationReceipt:
    receipt_id: str
    plan_id: str
    endpoint: ApprovedEndpoint
    action: str
    attempt_id: str
    approved: bool
    engagement_id: str
    authority_id: str
    issued_at: str
    expires_at: str


@dataclass(frozen=True)
class VersionedReproduction:
    reference: str
    endpoint: ApprovedEndpoint
    affected_version: str
    remediated_version: str
    steps: tuple[str, ...]
    expected_proof: str
    remediation: str

    def is_issue_143_for(self, endpoint: ApprovedEndpoint, observed_version: str) -> bool:
        return (
            self.reference == "#143"
            and self.endpoint == endpoint
            and self.affected_version == observed_version
            and all((self.affected_version, self.remediated_version, self.steps, self.expected_proof, self.remediation))
        )


@dataclass(frozen=True)
class ValidationFinding:
    finding_id: str
    observation: str
    evidence: str
    impact: str
    remediation: str
    detection: str

    @property
    def is_complete(self) -> bool:
        return all(
            value.strip()
            for value in (
                self.finding_id,
                self.observation,
                self.evidence,
                self.impact,
                self.remediation,
                self.detection,
            )
        )


@dataclass(frozen=True)
class TrustedValidationReproduction:
    reproduction: VersionedReproduction
    finding: ValidationFinding
    sha256: str


def load_trusted_issue_143_reproduction(endpoint: ApprovedEndpoint) -> TrustedValidationReproduction:
    """Load the immutable repository-owned issue #143 reproduction for an endpoint."""
    reproduction = VersionedReproduction(
        reference="#143",
        endpoint=endpoint,
        affected_version="redis-lab-5.0",
        remediated_version="redis-lab-7.2-protected",
        steps=(
            "connect to the approved endpoint",
            "send PING without credentials",
            "record the response",
        ),
        expected_proof="+PONG",
        remediation="require authentication and upgrade to the protected fixture",
    )
    finding = ValidationFinding(
        finding_id="COPS-LAB-143",
        observation="The affected disposable Redis fixture accepted an unauthenticated command.",
        evidence="The fixture retained a candidate audit record for correlated passive verification.",
        impact="An unauthenticated peer could invoke commands exposed by the fixture.",
        remediation="Require authentication and upgrade to the protected fixture.",
        detection="Alert on unauthenticated Redis commands and unexpected client addresses.",
    )
    payload = json.dumps(
        {"reproduction": asdict(reproduction), "finding": asdict(finding)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return TrustedValidationReproduction(reproduction, finding, sha256(payload).hexdigest())


@dataclass(frozen=True)
class ValidationProbeOutput:
    protocol_evidence: tuple[str, ...]
    dimensions: Mapping[str, str]
    candidate: bool = False
    effect_evidence: tuple[str, ...] = ()
    proof_succeeded: bool = False
    cleanup_evidence: tuple[str, ...] = ()
    reproduction: VersionedReproduction | None = None
    finding: ValidationFinding | None = None
    tokens: int = 0
    cost_microunits: int = 0
    retained_output_bytes: int = 0
    audit_reference: str = ""


@dataclass(frozen=True)
class ValidationEvidenceVerification:
    """Evidence correlated from fixture-owned audit data outside provider output."""

    approval_receipt_id: str
    plan_id: str
    attempt_id: str
    evidence_sha256: str
    endpoint: ApprovedEndpoint
    action: str
    observed_version: str
    protocol_evidence: tuple[str, ...]
    dimensions: Mapping[str, str]
    verified_at: str
    audit_recorded_at: str
    dispatch_correlation_id: str
    reproduction_sha256: str = ""
    candidate_verified: bool = False
    finding_effect: str = ""
    effect_evidence: tuple[str, ...] = ()
    finding_effect_verified: bool = False
    authorized_use_evidence: tuple[str, ...] = ()
    authorized_use_verified: bool = False
    cleanup_evidence: tuple[str, ...] = ()
    cleanup_verified: bool = False
    audit_reference: str = ""


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    reason: str
    evidence_limit: str


@dataclass(frozen=True)
class ValidationActionResult:
    status: str
    reason: str
    plan_id: str
    attempt_id: str
    action: str | None = None
    approval_receipt_id: str | None = None
    endpoint: ApprovedEndpoint | None = None
    observed_version: str | None = None
    reproduction_reference: str | None = None
    reproduction_sha256: str | None = None
    reproduction_expected_proof: str | None = None
    observed_exposure: bool = False
    candidate: bool = False
    verified_finding: bool = False
    successful_authorized_use: bool = False
    protocol_evidence: tuple[str, ...] = ()
    effect_evidence: tuple[str, ...] = ()
    authorized_use_evidence: tuple[str, ...] = ()
    cleanup_evidence: tuple[str, ...] = ()
    dimensions: Mapping[str, str] | None = None
    finding_id: str | None = None
    remediation: str | None = None
    attack_mappings: tuple[AttackMapping, ...] = ()
    coverage: Mapping[str, str] | None = None
    prerequisite_receipt: ValidationPrerequisiteReceipt | None = None


@dataclass(frozen=True)
class ValidationPrerequisiteReceipt:
    """Durable, single-use provenance for a controlled proof prerequisite."""

    receipt_id: str
    plan_id: str
    endpoint: ApprovedEndpoint
    source_attempt_id: str
    source_approval_receipt_id: str
    source_action: str
    evidence_sha256: str
    reproduction_sha256: str
    observed_version: str
    state: str = "candidate_verified"


@dataclass(frozen=True)
class ValidationDispatchContext:
    """Executor-owned identity carried through provider and passive audit evidence."""

    plan_id: str
    attempt_id: str
    approval_receipt_id: str
    action: str
    correlation_id: str


Provider = Callable[[ServiceValidationPlan, str, ValidationDispatchContext], ValidationProbeOutput]
# Ledger receipt uniqueness is local to one SQLite database. Authorization gates
# must reject receipt reuse across every ledger database for an engagement.
AuthorizationGate = Callable[[ServiceValidationPlan, ValidationSelection, str], AuthorizationReceipt]
EvidenceVerifier = Callable[
    [
        ServiceValidationPlan,
        ValidationSelection,
        AuthorizationReceipt,
        ValidationProbeOutput,
        ValidationDispatchContext,
    ],
    ValidationEvidenceVerification,
]


def _result(status: str, reason: str, plan: ServiceValidationPlan, attempt_id: str) -> ValidationActionResult:
    return ValidationActionResult(
        status=status,
        reason=reason,
        plan_id=plan.plan_id,
        attempt_id=attempt_id,
        endpoint=plan.endpoint,
    )


def _evidence_complete(verification: ValidationEvidenceVerification) -> bool:
    if not _verification_shape_is_valid(verification):
        return False
    return (
        bool(verification.protocol_evidence)
        and bool(verification.observed_version.strip())
        and all(
            isinstance(verification.dimensions.get(dimension), str) and bool(verification.dimensions[dimension].strip())
            for dimension in _DIMENSIONS
        )
    )


def _verified_during(value: str, started: datetime, finished: datetime) -> bool:
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return False
    if observed.tzinfo is None:
        return False
    observed = observed.astimezone(UTC)
    return started <= observed <= finished


def _aware_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _usage_is_bounded(output: ValidationProbeOutput) -> bool:
    return all(
        type(value) is int and 0 <= value <= 2**63 - 1
        for value in (output.tokens, output.cost_microunits, output.retained_output_bytes)
    )


def _string_tuple(value: object) -> bool:
    return isinstance(value, tuple) and all(isinstance(item, str) and bool(item.strip()) for item in value)


def _string_mapping(value: object) -> bool:
    return isinstance(value, Mapping) and all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    )


def _probe_output_shape_is_valid(output: ValidationProbeOutput) -> bool:
    reproduction = output.reproduction
    finding = output.finding
    return bool(
        _string_tuple(output.protocol_evidence)
        and _string_mapping(output.dimensions)
        and type(output.candidate) is bool
        and _string_tuple(output.effect_evidence)
        and type(output.proof_succeeded) is bool
        and _string_tuple(output.cleanup_evidence)
        and isinstance(output.audit_reference, str)
        and (
            reproduction is None
            or (
                isinstance(reproduction, VersionedReproduction)
                and isinstance(reproduction.reference, str)
                and isinstance(reproduction.endpoint, ApprovedEndpoint)
                and isinstance(reproduction.affected_version, str)
                and isinstance(reproduction.remediated_version, str)
                and _string_tuple(reproduction.steps)
                and isinstance(reproduction.expected_proof, str)
                and isinstance(reproduction.remediation, str)
            )
        )
        and (
            finding is None
            or (
                isinstance(finding, ValidationFinding)
                and all(
                    isinstance(value, str)
                    for value in (
                        finding.finding_id,
                        finding.observation,
                        finding.evidence,
                        finding.impact,
                        finding.remediation,
                        finding.detection,
                    )
                )
            )
        )
        and _usage_is_bounded(output)
    )


def _verification_shape_is_valid(verification: ValidationEvidenceVerification) -> bool:
    return bool(
        isinstance(verification.approval_receipt_id, str)
        and isinstance(verification.plan_id, str)
        and isinstance(verification.attempt_id, str)
        and isinstance(verification.evidence_sha256, str)
        and isinstance(verification.endpoint, ApprovedEndpoint)
        and isinstance(verification.action, str)
        and isinstance(verification.observed_version, str)
        and _string_tuple(verification.protocol_evidence)
        and _string_mapping(verification.dimensions)
        and isinstance(verification.verified_at, str)
        and isinstance(verification.audit_recorded_at, str)
        and isinstance(verification.dispatch_correlation_id, str)
        and isinstance(verification.reproduction_sha256, str)
        and type(verification.candidate_verified) is bool
        and isinstance(verification.finding_effect, str)
        and _string_tuple(verification.effect_evidence)
        and type(verification.finding_effect_verified) is bool
        and _string_tuple(verification.authorized_use_evidence)
        and type(verification.authorized_use_verified) is bool
        and _string_tuple(verification.cleanup_evidence)
        and type(verification.cleanup_verified) is bool
        and isinstance(verification.audit_reference, str)
    )


def _prerequisite_payload(receipt: ValidationPrerequisiteReceipt) -> dict[str, object]:
    return asdict(receipt)


def _new_prerequisite_receipt(
    plan: ServiceValidationPlan,
    request: AttemptRequest,
    approval: AuthorizationReceipt,
    trusted: TrustedValidationReproduction,
    observed_version: str,
) -> ValidationPrerequisiteReceipt:
    payload: dict[str, object] = {
        "plan_id": plan.plan_id,
        "endpoint": asdict(plan.endpoint),
        "source_attempt_id": request.attempt_id,
        "source_approval_receipt_id": approval.receipt_id,
        "source_action": "low_impact_validation",
        "evidence_sha256": plan.evidence_sha256,
        "reproduction_sha256": trusted.sha256,
        "observed_version": observed_version,
        "state": "candidate_verified",
    }
    receipt_id = (
        "validation-prereq:"
        + sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    )
    return ValidationPrerequisiteReceipt(
        receipt_id=receipt_id,
        plan_id=plan.plan_id,
        endpoint=plan.endpoint,
        source_attempt_id=request.attempt_id,
        source_approval_receipt_id=approval.receipt_id,
        source_action="low_impact_validation",
        evidence_sha256=plan.evidence_sha256,
        reproduction_sha256=trusted.sha256,
        observed_version=observed_version,
    )


def execute_service_validation_action(
    plan: ServiceValidationPlan,
    selection: ValidationSelection,
    *,
    ledger: AssessmentBudgetLedger,
    request: AttemptRequest,
    authorization_gate: AuthorizationGate,
    provider: Provider | None,
    evidence_verifier: EvidenceVerifier | None,
    prerequisite_receipt: ValidationPrerequisiteReceipt | None = None,
) -> ValidationActionResult:
    """Run one exact action; every retry needs a new ledger and approval identity."""
    if selection.plan_id != plan.plan_id or not service_validation_plan_is_intact(plan):
        return _result("blocked_selection", "selection does not bind the exact plan", plan, request.attempt_id)
    if provider is None or evidence_verifier is None:
        return _result(
            "provider_unavailable",
            "no native provider and passive evidence verifier are registered",
            plan,
            request.attempt_id,
        )
    trusted = load_trusted_issue_143_reproduction(plan.endpoint)
    issue_143_route = plan.service == "redis" and plan.skill_id == "network-data-services"
    if selection.action == "controlled_proof" and (
        not issue_143_route
        or prerequisite_receipt is None
        or prerequisite_receipt.plan_id != plan.plan_id
        or prerequisite_receipt.endpoint != plan.endpoint
        or prerequisite_receipt.source_action != "low_impact_validation"
        or prerequisite_receipt.evidence_sha256 != plan.evidence_sha256
        or prerequisite_receipt.reproduction_sha256 != trusted.sha256
        or prerequisite_receipt.observed_version != trusted.reproduction.affected_version
        or prerequisite_receipt.state != "candidate_verified"
    ):
        return _result(
            "blocked_prerequisite", "controlled proof requires a versioned #143 candidate", plan, request.attempt_id
        )

    try:
        reserved = ledger.reserve(request)
        if reserved.state != "reserved":
            return _result("budget_denied", "attempt identifier is not a fresh reservation", plan, request.attempt_id)
    except BudgetDenied as exc:
        return _result("budget_denied", str(exc), plan, request.attempt_id)

    try:
        approval = authorization_gate(plan, selection, request.attempt_id)
    except Exception as exc:
        ledger.release_undispatched(request.attempt_id)
        return _result(
            "authorization_error",
            f"authorization gate did not return a receipt: {type(exc).__name__}",
            plan,
            request.attempt_id,
        )

    approval_now = datetime.now(UTC)
    approval_issued_at = _aware_timestamp(approval.issued_at) if isinstance(approval, AuthorizationReceipt) else None
    approval_expires_at = _aware_timestamp(approval.expires_at) if isinstance(approval, AuthorizationReceipt) else None
    exact_approval = bool(
        isinstance(approval, AuthorizationReceipt)
        and type(approval.approved) is bool
        and approval.approved
        and isinstance(approval.receipt_id, str)
        and bool(approval.receipt_id.strip())
        and isinstance(approval.plan_id, str)
        and approval.plan_id == plan.plan_id
        and isinstance(approval.endpoint, ApprovedEndpoint)
        and approval.endpoint == plan.endpoint
        and isinstance(approval.action, str)
        and approval.action == selection.action
        and isinstance(approval.attempt_id, str)
        and approval.attempt_id == request.attempt_id
        and isinstance(approval.engagement_id, str)
        and approval.engagement_id == ledger.policy.engagement_id
        and isinstance(approval.authority_id, str)
        and bool(approval.authority_id.strip())
        and approval_issued_at is not None
        and approval_expires_at is not None
        and approval_issued_at < approval_expires_at
        and approval_issued_at <= approval_now <= approval_expires_at
    )
    if not exact_approval:
        ledger.release_undispatched(request.attempt_id)
        return _result(
            "authorization_denied", "approval does not bind the exact action and endpoint", plan, request.attempt_id
        )

    dispatch_context = ValidationDispatchContext(
        plan_id=plan.plan_id,
        attempt_id=request.attempt_id,
        approval_receipt_id=approval.receipt_id,
        action=selection.action,
        correlation_id=secrets.token_hex(32),
    )
    dispatch_intent = {
        "schema_version": "cops.service-validation-dispatch/v1",
        "engagement_id": ledger.policy.engagement_id,
        "plan_id": plan.plan_id,
        "plan_digest": service_validation_plan_digest(plan),
        "endpoint": asdict(plan.endpoint),
        "action": selection.action,
        "attempt_id": request.attempt_id,
        "approval_receipt_id": approval.receipt_id,
        "approval_authority_id": approval.authority_id,
        "approval_issued_at": approval.issued_at,
        "approval_expires_at": approval.expires_at,
        "dispatch_correlation_id": dispatch_context.correlation_id,
    }

    try:
        if selection.action == "controlled_proof" and prerequisite_receipt is not None:
            ledger.mark_dispatched(
                request.attempt_id,
                approval_receipt_id=approval.receipt_id,
                dispatch_intent=dispatch_intent,
                prerequisite_receipt_id=prerequisite_receipt.receipt_id,
                expected_prerequisite=_prerequisite_payload(prerequisite_receipt),
            )
        else:
            ledger.mark_dispatched(
                request.attempt_id,
                approval_receipt_id=approval.receipt_id,
                dispatch_intent=dispatch_intent,
            )
    except Exception as exc:
        try:
            attempt_state = ledger.get_attempt(request.attempt_id).state
        except Exception:
            attempt_state = "unknown"
        if attempt_state == "reserved":
            try:
                ledger.release_undispatched(request.attempt_id)
            except (BudgetDenied, ValueError):
                pass
        else:
            try:
                ledger.mark_uncertain(request.attempt_id)
            except (BudgetDenied, ValueError):
                pass
        return _result(
            (
                "blocked_prerequisite"
                if attempt_state == "reserved" and selection.action == "controlled_proof"
                else "dispatch_error"
                if attempt_state == "reserved"
                else "dispatch_uncertain"
            ),
            (
                f"attempt was not dispatched: {type(exc).__name__}"
                if attempt_state == "reserved"
                else f"dispatch state could not be confirmed: {type(exc).__name__}"
            ),
            plan,
            request.attempt_id,
        )

    dispatch_started_at = datetime.now(UTC)
    try:
        output = provider(plan, selection.action, dispatch_context)
    except Exception as exc:
        try:
            ledger.mark_uncertain(request.attempt_id)
        except (BudgetDenied, ValueError):
            pass
        return _result(
            "dispatch_uncertain", f"provider did not return a receipt: {type(exc).__name__}", plan, request.attempt_id
        )
    dispatch_finished_at = datetime.now(UTC)

    if not isinstance(output, ValidationProbeOutput) or not _probe_output_shape_is_valid(output):
        try:
            ledger.mark_uncertain(request.attempt_id)
        except (BudgetDenied, ValueError):
            pass
        return _result(
            "dispatch_uncertain",
            "provider returned malformed or unbounded usage evidence",
            plan,
            request.attempt_id,
        )

    verification_started_at = datetime.now(UTC)
    try:
        candidate_verification = evidence_verifier(plan, selection, approval, output, dispatch_context)
    except Exception as exc:
        verification = None
        verification_error = type(exc).__name__
    else:
        if isinstance(candidate_verification, ValidationEvidenceVerification) and _verification_shape_is_valid(
            candidate_verification
        ):
            verification = candidate_verification
            verification_error = ""
        elif isinstance(candidate_verification, ValidationEvidenceVerification):
            verification = None
            verification_error = "malformed evidence fields"
        else:
            verification = None
            verification_error = f"invalid return type: {type(candidate_verification).__name__}"
    verification_finished_at = datetime.now(UTC)

    exact_verification = bool(
        verification is not None
        and verification.approval_receipt_id == approval.receipt_id
        and verification.plan_id == plan.plan_id
        and verification.attempt_id == request.attempt_id
        and verification.evidence_sha256 == plan.evidence_sha256
        and verification.endpoint == plan.endpoint
        and verification.action == selection.action
        and verification.dispatch_correlation_id == dispatch_context.correlation_id
        and bool(output.audit_reference)
        and verification.audit_reference == output.audit_reference
        and _verified_during(verification.audit_recorded_at, dispatch_started_at, dispatch_finished_at)
        and _verified_during(verification.verified_at, verification_started_at, verification_finished_at)
    )
    if verification is None or not exact_verification:
        try:
            ledger.mark_uncertain(request.attempt_id)
        except (BudgetDenied, ValueError):
            pass
        detail = f": {verification_error}" if verification_error else ""
        return _result(
            "dispatch_uncertain",
            f"passive evidence could not be bound to the dispatched action{detail}",
            plan,
            request.attempt_id,
        )
    complete = exact_verification and verification is not None and _evidence_complete(verification)
    candidate_claimed = bool(
        output.candidate
        or output.reproduction is not None
        or output.finding is not None
        or (verification is not None and verification.candidate_verified)
    )
    candidate = (
        issue_143_route
        and complete
        and output.candidate
        and verification is not None
        and verification.candidate_verified
        and verification.reproduction_sha256 == trusted.sha256
        and output.reproduction == trusted.reproduction
        and output.finding == trusted.finding
        and trusted.reproduction.affected_version == verification.observed_version
    )
    invalid_candidate_claim = candidate_claimed and not candidate
    reproduction = trusted.reproduction if candidate else None
    finding = trusted.finding if candidate else None
    prior_binding = bool(
        prerequisite_receipt is not None
        and prerequisite_receipt.reproduction_sha256 == trusted.sha256
        and prerequisite_receipt.observed_version == trusted.reproduction.affected_version
    )
    proof_complete = bool(
        verification is not None
        and exact_verification
        and verification.finding_effect_verified
        and verification.finding_effect == (reproduction.expected_proof if reproduction else "")
        and verification.effect_evidence
        and verification.cleanup_verified
        and verification.cleanup_evidence
    )
    verified = selection.action == "controlled_proof" and complete and proof_complete and candidate and prior_binding
    successful_use = bool(
        selection.action == "controlled_proof"
        and verified
        and verification is not None
        and verification.authorized_use_verified
        and verification.authorized_use_evidence
        and verification.cleanup_verified
    )
    effect_observed_without_cleanup = bool(
        selection.action == "controlled_proof"
        and exact_verification
        and verification is not None
        and verification.finding_effect_verified
        and verification.effect_evidence
        and (not verification.cleanup_verified or not verification.cleanup_evidence)
    )
    if effect_observed_without_cleanup:
        try:
            ledger.mark_uncertain(request.attempt_id)
        except (BudgetDenied, ValueError):
            pass
        return ValidationActionResult(
            status="dispatch_uncertain",
            reason="the controlled effect was observed but cleanup was not positively verified",
            plan_id=plan.plan_id,
            attempt_id=request.attempt_id,
            action=selection.action,
            approval_receipt_id=approval.receipt_id,
            endpoint=plan.endpoint,
            observed_version=verification.observed_version,
            protocol_evidence=verification.protocol_evidence,
            effect_evidence=verification.effect_evidence,
            cleanup_evidence=verification.cleanup_evidence,
            dimensions=dict(verification.dimensions),
        )
    status = (
        "completed"
        if complete and ((selection.action == "low_impact_validation" and not invalid_candidate_claim) or verified)
        else "insufficient_evidence"
    )
    new_prerequisite = (
        _new_prerequisite_receipt(
            plan,
            request,
            approval,
            trusted,
            verification.observed_version,
        )
        if status == "completed"
        and selection.action == "low_impact_validation"
        and candidate
        and verification is not None
        else None
    )
    try:
        ledger.reconcile(
            Receipt(
                receipt_id=f"service-validation:{request.attempt_id}",
                attempt_id=request.attempt_id,
                outcome="completed" if status == "completed" else "failed",
                tokens=output.tokens,
                cost_microunits=output.cost_microunits,
                retained_output_bytes=output.retained_output_bytes,
            ),
            validation_prerequisite_id=new_prerequisite.receipt_id if new_prerequisite else None,
            validation_prerequisite=_prerequisite_payload(new_prerequisite) if new_prerequisite else None,
        )
    except Exception as exc:
        try:
            ledger.mark_uncertain(request.attempt_id)
        except (BudgetDenied, ValueError):
            pass
        return _result(
            "dispatch_uncertain",
            f"usage could not be settled: {type(exc).__name__}",
            plan,
            request.attempt_id,
        )
    verified_dimensions = verification.dimensions if exact_verification and verification is not None else {}
    coverage = {
        dimension: ("tested" if verified_dimensions.get(dimension) else "untested") for dimension in _DIMENSIONS
    }
    coverage["protocol"] = "tested" if complete else "untested"
    coverage["effect"] = "tested" if proof_complete else "untested"
    coverage["authorized_use"] = "tested" if successful_use else "untested"
    coverage["cleanup"] = (
        "tested" if exact_verification and verification is not None and verification.cleanup_verified else "untested"
    )
    coverage["reproduction"] = "versioned-#143" if candidate else "unverified"
    for field in ("observation", "evidence", "impact", "remediation", "detection"):
        coverage[f"finding_{field}"] = "documented" if candidate else "unverified"
    mappings = (AttackMapping("T1046", "The approved service responded to a bounded probe.", "Shows exposure only."),)
    if candidate:
        mappings += (
            AttackMapping(
                "T1210",
                "A versioned service candidate matched the #143 reproduction.",
                "Candidate until separate controlled proof records effect and cleanup.",
            ),
        )
    return ValidationActionResult(
        status=status,
        reason=(
            "correlated passive evidence satisfied the selected gate"
            if status == "completed"
            else f"required correlated passive evidence is incomplete{': ' + verification_error if verification_error else ''}"
        ),
        plan_id=plan.plan_id,
        attempt_id=request.attempt_id,
        action=selection.action,
        approval_receipt_id=approval.receipt_id,
        endpoint=plan.endpoint,
        observed_version=verification.observed_version if exact_verification and verification is not None else None,
        reproduction_reference=reproduction.reference if candidate and reproduction is not None else None,
        reproduction_sha256=trusted.sha256 if candidate else None,
        reproduction_expected_proof=reproduction.expected_proof if candidate and reproduction is not None else None,
        observed_exposure=complete,
        candidate=candidate,
        verified_finding=verified,
        successful_authorized_use=successful_use,
        protocol_evidence=verification.protocol_evidence if exact_verification and verification is not None else (),
        effect_evidence=verification.effect_evidence if exact_verification and verification is not None else (),
        authorized_use_evidence=(
            verification.authorized_use_evidence if exact_verification and verification is not None else ()
        ),
        cleanup_evidence=verification.cleanup_evidence if exact_verification and verification is not None else (),
        dimensions=dict(verified_dimensions),
        finding_id=finding.finding_id if candidate and finding is not None else None,
        remediation=finding.remediation if candidate and finding is not None else None,
        attack_mappings=mappings,
        coverage=coverage,
        prerequisite_receipt=new_prerequisite,
    )
