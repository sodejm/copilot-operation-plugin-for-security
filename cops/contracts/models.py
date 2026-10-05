"""Data models and factory methods for COPS operational and engagement contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .lifecycle import validate_transition
from .validation import build_action_plan_digest, evaluate_run_result, validate_contract


@dataclass
class Engagement:
    """Authorized cybersecurity testing engagement definition."""

    schema_version: str
    engagement_id: str
    name: str
    status: str
    scope: dict[str, list[str]]
    window: dict[str, str]
    operator: str
    rules_of_engagement: dict[str, Any]
    created_at: str
    metadata: dict[str, Any] | None = None
    mode: str | None = None
    budget: dict[str, Any] | None = None
    credential_references: list[str] | None = None

    def transition_to(self, next_state: str) -> None:
        """Attempt to transition engagement to a new lifecycle state."""
        validate_transition(self.status, next_state, "engagement")
        self.status = next_state

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "name": self.name,
            "status": self.status,
            "scope": self.scope,
            "window": self.window,
            "operator": self.operator,
            "rules_of_engagement": self.rules_of_engagement,
            "created_at": self.created_at,
        }
        if self.mode is not None:
            result["mode"] = self.mode
        if self.budget is not None:
            result["budget"] = self.budget
        if self.credential_references is not None:
            result["credential_references"] = self.credential_references
        if self.metadata is not None:
            result["metadata"] = self.metadata
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Engagement:
        validate_contract(data, "engagement")
        return cls(
            schema_version=data["schema_version"],
            engagement_id=data["engagement_id"],
            name=data["name"],
            status=data["status"],
            scope=data["scope"],
            window=data["window"],
            operator=data["operator"],
            rules_of_engagement=data["rules_of_engagement"],
            created_at=data["created_at"],
            metadata=data.get("metadata"),
            mode=data.get("mode"),
            budget=data.get("budget"),
            credential_references=data.get("credential_references"),
        )


@dataclass(frozen=True)
class Scenario:
    """Security assessment or attack path scenario definition."""

    schema_version: str
    scenario_id: str
    family_id: str
    title: str
    description: str
    mitre_attack: dict[str, list[str]]
    provenance: dict[str, str]
    environment: dict[str, Any]
    safety_profile: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "family_id": self.family_id,
            "title": self.title,
            "description": self.description,
            "mitre_attack": self.mitre_attack,
            "provenance": self.provenance,
            "environment": self.environment,
            "safety_profile": self.safety_profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scenario:
        validate_contract(data, "scenario")
        return cls(
            schema_version=data["schema_version"],
            scenario_id=data["scenario_id"],
            family_id=data["family_id"],
            title=data["title"],
            description=data["description"],
            mitre_attack=data["mitre_attack"],
            provenance=data["provenance"],
            environment=data["environment"],
            safety_profile=data["safety_profile"],
        )


@dataclass
class ActionPlan:
    """Immutable sequence of authorized operations bound to a scenario and engagement."""

    schema_version: str
    plan_id: str
    engagement_id: str
    scenario_id: str
    status: str
    target: str
    specialist_id: str
    operations: list[dict[str, Any]]
    limits: dict[str, Any]
    credential_references: list[str]
    plan_digest: str
    created_at: str
    platform_prerequisites: list[str] | None = None

    def transition_to(self, next_state: str) -> None:
        """Attempt to transition action plan to a new lifecycle state."""
        validate_transition(self.status, next_state, "action_plan")
        self.status = next_state

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "engagement_id": self.engagement_id,
            "scenario_id": self.scenario_id,
            "status": self.status,
            "target": self.target,
            "specialist_id": self.specialist_id,
            "operations": self.operations,
            "limits": self.limits,
            "credential_references": self.credential_references,
            "plan_digest": self.plan_digest,
            "created_at": self.created_at,
        }
        if self.platform_prerequisites is not None:
            result["platform_prerequisites"] = self.platform_prerequisites
        return result

    @classmethod
    def create(
        cls,
        *,
        plan_id: str,
        engagement_id: str,
        scenario_id: str,
        target: str,
        specialist_id: str,
        operations: list[dict[str, Any]],
        limits: dict[str, Any],
        credential_references: list[str],
        created_at: str,
        status: str = "draft",
        platform_prerequisites: list[str] | None = None,
    ) -> ActionPlan:
        computed_digest = build_action_plan_digest(
            target=target,
            specialist_id=specialist_id,
            operations=operations,
            limits=limits,
        )
        plan = cls(
            schema_version="cops.action-plan/v1",
            plan_id=plan_id,
            engagement_id=engagement_id,
            scenario_id=scenario_id,
            status=status,
            target=target,
            specialist_id=specialist_id,
            operations=operations,
            limits=limits,
            credential_references=credential_references,
            plan_digest=computed_digest,
            created_at=created_at,
            platform_prerequisites=platform_prerequisites,
        )
        validate_contract(plan.to_dict(), "action_plan")
        return plan

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActionPlan:
        validate_contract(data, "action_plan")
        return cls(
            schema_version=data["schema_version"],
            plan_id=data["plan_id"],
            engagement_id=data["engagement_id"],
            scenario_id=data["scenario_id"],
            status=data["status"],
            target=data["target"],
            specialist_id=data["specialist_id"],
            operations=data["operations"],
            limits=data["limits"],
            credential_references=data["credential_references"],
            plan_digest=data["plan_digest"],
            created_at=data["created_at"],
            platform_prerequisites=data.get("platform_prerequisites"),
        )


@dataclass
class ExecutionAuthorization:
    """Cryptographically bound, operator-authenticated approval envelope for an action plan."""

    schema_version: str
    authorization_id: str
    action_plan_id: str
    plan_digest: str
    engagement_id: str
    operator: str
    status: str
    issued_at: str
    authorized_until_utc: str
    bound_parameters: dict[str, Any]
    approval_mode: str
    signature_digest: str
    consumed_at: str | None = None
    consumed_by_worker: str | None = None

    def transition_to(self, next_state: str) -> None:
        """Attempt to transition execution authorization to a new lifecycle state."""
        validate_transition(self.status, next_state, "execution_authorization")
        self.status = next_state

    def is_valid_at(self, current_time_iso: str | None = None) -> bool:
        """Check if authorization is in approved state and within the authorized time window."""
        from datetime import datetime, timezone
        from cops.evidence.canonical import timestamp

        if self.status != "approved":
            return False
        if current_time_iso is not None:
            now_dt = timestamp(current_time_iso)
        else:
            now_dt = datetime.now(timezone.utc)
        return now_dt <= timestamp(self.authorized_until_utc)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "authorization_id": self.authorization_id,
            "action_plan_id": self.action_plan_id,
            "plan_digest": self.plan_digest,
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "status": self.status,
            "issued_at": self.issued_at,
            "authorized_until_utc": self.authorized_until_utc,
            "bound_parameters": self.bound_parameters,
            "approval_mode": self.approval_mode,
            "signature_digest": self.signature_digest,
        }
        if self.consumed_at is not None:
            data["consumed_at"] = self.consumed_at
        if self.consumed_by_worker is not None:
            data["consumed_by_worker"] = self.consumed_by_worker
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionAuthorization:
        validate_contract(data, "execution_authorization")
        return cls(
            schema_version=data["schema_version"],
            authorization_id=data["authorization_id"],
            action_plan_id=data["action_plan_id"],
            plan_digest=data["plan_digest"],
            engagement_id=data["engagement_id"],
            operator=data["operator"],
            status=data["status"],
            issued_at=data["issued_at"],
            authorized_until_utc=data["authorized_until_utc"],
            bound_parameters=data["bound_parameters"],
            approval_mode=data["approval_mode"],
            signature_digest=data["signature_digest"],
            consumed_at=data.get("consumed_at"),
            consumed_by_worker=data.get("consumed_by_worker"),
        )


@dataclass(frozen=True)
class RunResult:
    """Outcome of action plan execution, retaining non-success states explicitly."""

    schema_version: str
    result_id: str
    plan_id: str
    engagement_id: str
    status: str
    started_at: str
    finished_at: str
    status_details: dict[str, Any]
    evidence_records: list[str]
    artifacts: list[dict[str, Any]]
    cleanup_status: str
    worker_identity: str
    exit_code: int | None = None

    def is_successful(self) -> bool:
        """Return True only if status is strictly 'success'."""
        return evaluate_run_result(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "result_id": self.result_id,
            "plan_id": self.plan_id,
            "engagement_id": self.engagement_id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "status_details": self.status_details,
            "evidence_records": self.evidence_records,
            "artifacts": self.artifacts,
            "cleanup_status": self.cleanup_status,
            "worker_identity": self.worker_identity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunResult:
        validate_contract(data, "run_result")
        return cls(
            schema_version=data["schema_version"],
            result_id=data["result_id"],
            plan_id=data["plan_id"],
            engagement_id=data["engagement_id"],
            status=data["status"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            exit_code=data.get("exit_code"),
            status_details=data["status_details"],
            evidence_records=data["evidence_records"],
            artifacts=data["artifacts"],
            cleanup_status=data["cleanup_status"],
            worker_identity=data["worker_identity"],
        )


@dataclass(frozen=True)
class Finding:
    """Normalized security finding bound to run result evidence and engagement scope."""

    schema_version: str
    finding_id: str
    engagement_id: str
    result_id: str
    scenario_id: str
    title: str
    severity: str
    classification: str
    verification: str
    confidence: str
    claim: str
    evidence_references: list[str]
    mitre_attack: list[str]
    remediation: str
    uncertainty: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "engagement_id": self.engagement_id,
            "result_id": self.result_id,
            "scenario_id": self.scenario_id,
            "title": self.title,
            "severity": self.severity,
            "classification": self.classification,
            "verification": self.verification,
            "confidence": self.confidence,
            "claim": self.claim,
            "evidence_references": self.evidence_references,
            "mitre_attack": self.mitre_attack,
            "remediation": self.remediation,
            "uncertainty": self.uncertainty,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        validate_contract(data, "finding")
        return cls(
            schema_version=data["schema_version"],
            finding_id=data["finding_id"],
            engagement_id=data["engagement_id"],
            result_id=data["result_id"],
            scenario_id=data["scenario_id"],
            title=data["title"],
            severity=data["severity"],
            classification=data["classification"],
            verification=data["verification"],
            confidence=data["confidence"],
            claim=data["claim"],
            evidence_references=data["evidence_references"],
            mitre_attack=data["mitre_attack"],
            remediation=data["remediation"],
            uncertainty=data["uncertainty"],
            created_at=data["created_at"],
        )


@dataclass(frozen=True)
class CleanupReceipt:
    """Receipt documenting cleanup and rollback actions for tracked side effects."""

    schema_version: str
    receipt_id: str
    plan_id: str
    engagement_id: str
    worker_identity: str
    status: str
    created_at: str
    completed_at: str
    cleaned_effects: list[dict[str, Any]]
    unresolved_effects: list[dict[str, Any]]
    evidence_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "engagement_id": self.engagement_id,
            "worker_identity": self.worker_identity,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "cleaned_effects": self.cleaned_effects,
            "unresolved_effects": self.unresolved_effects,
            "evidence_hash": self.evidence_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CleanupReceipt:
        validate_contract(data, "cleanup_receipt")
        return cls(
            schema_version=data["schema_version"],
            receipt_id=data["receipt_id"],
            plan_id=data["plan_id"],
            engagement_id=data["engagement_id"],
            worker_identity=data["worker_identity"],
            status=data["status"],
            created_at=data["created_at"],
            completed_at=data["completed_at"],
            cleaned_effects=data["cleaned_effects"],
            unresolved_effects=data["unresolved_effects"],
            evidence_hash=data["evidence_hash"],
        )
