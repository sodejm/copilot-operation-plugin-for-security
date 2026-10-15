"""Budgeted dispatcher boundary for operator-selected service validation.

Providers are injected adapters.  This coordinator does not infer permission,
select an action, or convert a port observation into a finding.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cops.assessment_budget import AssessmentBudgetLedger, AttemptRequest, BudgetDenied, Receipt

from .service_entry_validation import ApprovedEndpoint, ServiceValidationPlan

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


@dataclass(frozen=True)
class ValidationEvidenceVerification:
    """Evidence independently verified outside the specialist provider."""

    approval_receipt_id: str
    endpoint: ApprovedEndpoint
    action: str
    observed_version: str
    protocol_evidence: tuple[str, ...]
    dimensions: Mapping[str, str]
    candidate_verified: bool = False
    finding_effect: str = ""
    effect_evidence: tuple[str, ...] = ()
    finding_effect_verified: bool = False
    authorized_use_evidence: tuple[str, ...] = ()
    authorized_use_verified: bool = False
    cleanup_evidence: tuple[str, ...] = ()
    cleanup_verified: bool = False


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


Provider = Callable[[ServiceValidationPlan, str], ValidationProbeOutput]
AuthorizationGate = Callable[[ServiceValidationPlan, ValidationSelection, str], AuthorizationReceipt]
EvidenceVerifier = Callable[
    [ServiceValidationPlan, ValidationSelection, AuthorizationReceipt, ValidationProbeOutput],
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
    return bool(verification.protocol_evidence) and bool(verification.observed_version.strip()) and all(
        isinstance(verification.dimensions.get(dimension), str)
        and bool(verification.dimensions[dimension].strip())
        for dimension in _DIMENSIONS
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
    prior_result: ValidationActionResult | None = None,
) -> ValidationActionResult:
    """Run one exact action; every retry needs a new ledger and approval identity."""
    if selection.plan_id != plan.plan_id:
        return _result("blocked_selection", "selection does not bind the exact plan", plan, request.attempt_id)
    if provider is None or evidence_verifier is None:
        return _result(
            "provider_unavailable",
            "no native provider and independent evidence verifier are registered",
            plan,
            request.attempt_id,
        )
    if selection.action == "controlled_proof" and (
        prior_result is None
        or not prior_result.candidate
        or prior_result.plan_id != plan.plan_id
        or prior_result.endpoint != plan.endpoint
        or not prior_result.observed_version
        or prior_result.reproduction_reference != "#143"
        or prior_result.coverage is None
        or prior_result.coverage.get("reproduction") != "versioned-#143"
    ):
        return _result("blocked_prerequisite", "controlled proof requires a versioned #143 candidate", plan, request.attempt_id)

    try:
        reserved = ledger.reserve(request)
        if reserved.state != "reserved":
            return _result("budget_denied", "attempt identifier is not a fresh reservation", plan, request.attempt_id)
        approval = authorization_gate(plan, selection, request.attempt_id)
        exact_approval = (
            approval.approved
            and bool(approval.receipt_id.strip())
            and approval.plan_id == plan.plan_id
            and approval.endpoint == plan.endpoint
            and approval.action == selection.action
            and approval.attempt_id == request.attempt_id
        )
        if not exact_approval:
            ledger.release_undispatched(request.attempt_id)
            return _result("authorization_denied", "approval does not bind the exact action and endpoint", plan, request.attempt_id)
        ledger.mark_dispatched(request.attempt_id)
        output = provider(plan, selection.action)
    except BudgetDenied as exc:
        return _result("budget_denied", str(exc), plan, request.attempt_id)
    except Exception as exc:
        try:
            ledger.mark_uncertain(request.attempt_id)
        except (BudgetDenied, ValueError):
            pass
        return _result("dispatch_uncertain", f"provider did not return a receipt: {type(exc).__name__}", plan, request.attempt_id)

    try:
        verification = evidence_verifier(plan, selection, approval, output)
    except Exception as exc:
        verification = None
        verification_error = type(exc).__name__
    else:
        verification_error = ""

    ledger.reconcile(
        Receipt(
            receipt_id=f"service-validation:{request.attempt_id}",
            attempt_id=request.attempt_id,
            outcome="completed",
            tokens=output.tokens,
            cost_microunits=output.cost_microunits,
            retained_output_bytes=output.retained_output_bytes,
        )
    )
    exact_verification = bool(
        verification is not None
        and verification.approval_receipt_id == approval.receipt_id
        and verification.endpoint == plan.endpoint
        and verification.action == selection.action
    )
    complete = exact_verification and verification is not None and _evidence_complete(verification)
    reproduction = output.reproduction
    finding = output.finding
    candidate = (
        complete
        and output.candidate
        and verification is not None
        and verification.candidate_verified
        and reproduction is not None
        and reproduction.is_issue_143_for(plan.endpoint, verification.observed_version)
        and finding is not None
        and finding.is_complete
    )
    prior_binding = bool(
        prior_result is not None
        and reproduction is not None
        and prior_result.observed_version == reproduction.affected_version
        and prior_result.reproduction_expected_proof == reproduction.expected_proof
    )
    proof_complete = bool(
        verification is not None
        and verification.finding_effect_verified
        and verification.finding_effect == (reproduction.expected_proof if reproduction else "")
        and verification.effect_evidence
        and verification.cleanup_verified
        and verification.cleanup_evidence
    )
    verified = (
        selection.action == "controlled_proof"
        and complete
        and proof_complete
        and candidate
        and prior_binding
    )
    successful_use = bool(
        selection.action == "controlled_proof"
        and verified
        and verification is not None
        and verification.authorized_use_verified
        and verification.authorized_use_evidence
        and verification.cleanup_verified
    )
    status = (
        "completed"
        if complete and (selection.action == "low_impact_validation" or verified or successful_use)
        else "insufficient_evidence"
    )
    verified_dimensions = verification.dimensions if exact_verification and verification is not None else {}
    coverage = {dimension: ("tested" if verified_dimensions.get(dimension) else "untested") for dimension in _DIMENSIONS}
    coverage["protocol"] = "tested" if complete else "untested"
    coverage["effect"] = "tested" if proof_complete else "untested"
    coverage["authorized_use"] = "tested" if successful_use else "untested"
    coverage["cleanup"] = "tested" if verification is not None and verification.cleanup_verified else "untested"
    coverage["reproduction"] = "versioned-#143" if candidate else "unverified"
    for field in ("observation", "evidence", "impact", "remediation", "detection"):
        coverage[f"finding_{field}"] = "documented" if candidate else "unverified"
    mappings = (
        AttackMapping("T1046", "The approved service responded to a bounded probe.", "Shows exposure only."),
    )
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
            "independent evidence satisfied the selected gate"
            if status == "completed"
            else f"required independent evidence is incomplete{': ' + verification_error if verification_error else ''}"
        ),
        plan_id=plan.plan_id,
        attempt_id=request.attempt_id,
        action=selection.action,
        approval_receipt_id=approval.receipt_id,
        endpoint=plan.endpoint,
        observed_version=verification.observed_version if exact_verification and verification is not None else None,
        reproduction_reference=reproduction.reference if candidate and reproduction is not None else None,
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
    )
