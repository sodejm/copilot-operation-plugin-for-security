"""Standard-library validation for COPS operational and engagement contracts."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from cops.evidence.canonical import EvidenceError, canonical, digest, timestamp
from cops.evidence.validation import _check
from .lifecycle import ContractError, RUN_RESULT_STATUSES

SCHEMAS: Path = Path(__file__).resolve().parents[2] / "catalog" / "schemas"

IDENTIFIER_PATTERNS: dict[str, re.Pattern[str]] = {
    "engagement": re.compile(r"^eng-[a-z0-9_-]{4,64}$"),
    "scenario": re.compile(r"^(scen-[a-z0-9_-]{4,64}|COPS-[A-Z0-9_.-]+)$"),
    "action_plan": re.compile(r"^plan-[a-z0-9_-]{4,64}$"),
    "run_result": re.compile(r"^res-[a-z0-9_-]{4,64}$"),
    "finding": re.compile(r"^find-[a-z0-9_-]{4,64}$"),
    "execution_authorization": re.compile(r"^auth-[a-z0-9_-]{8,64}$"),
}

SCHEMA_MAP: dict[str, str] = {
    "cops.engagement/v1": "engagement-contract.schema.json",
    "cops.scenario/v1": "scenario-contract.schema.json",
    "cops.action-plan/v1": "action-plan.schema.json",
    "cops.run-result/v1": "run-result.schema.json",
    "cops.finding/v1": "finding-contract.schema.json",
    "cops.execution-authorization/v1": "execution-authorization.schema.json",
}

TYPE_MAP: dict[str, str] = {
    "cops.engagement/v1": "engagement",
    "cops.scenario/v1": "scenario",
    "cops.action-plan/v1": "action_plan",
    "cops.run-result/v1": "run_result",
    "cops.finding/v1": "finding",
    "cops.execution-authorization/v1": "execution_authorization",
}


def validate_identifier(identifier: str, kind: str) -> None:
    """Validate that an identifier conforms to the required syntax for its kind."""
    if not isinstance(identifier, str):
        raise ContractError("malformed_identifier", f"identifier must be a string: {identifier!r}")
    pattern = IDENTIFIER_PATTERNS.get(kind)
    if not pattern:
        raise ContractError("invalid_contract", f"unknown identifier kind: {kind}")
    if not pattern.fullmatch(identifier):
        raise ContractError(
            "malformed_identifier",
            f"identifier '{identifier}' does not match required pattern for {kind}"
        )


def build_action_plan_digest(
    *,
    target: str,
    specialist_id: str,
    operations: list[dict[str, Any]],
    limits: dict[str, Any],
    max_bytes: int = 1024 * 1024,
) -> str:
    """Calculate deterministic canonical digest of an action plan payload."""
    payload = {
        "target": target,
        "specialist_id": specialist_id,
        "operations": operations,
        "limits": limits,
    }
    return digest(payload, max_bytes=max_bytes)


def evaluate_run_result(result: dict[str, Any]) -> bool:
    """Evaluate whether a run result represents an affirmative success.

    Returns False for partial, cancelled, failed, uncertain, or not-assessed states.
    """
    status = result.get("status")
    return status == "success"


def validate_contract(
    document: dict[str, Any],
    contract_type: str | None = None,
    *,
    max_bytes: int = 1024 * 1024,
    max_depth: int = 32,
) -> dict[str, Any]:
    """Validate an operational contract against its schema and invariant rules."""
    try:
        canonical(document, max_bytes=max_bytes, max_depth=max_depth)
    except EvidenceError as err:
        raise ContractError(err.code, f"canonical JSON check failed: {err}") from err

    version = document.get("schema_version")
    if not version or version not in SCHEMA_MAP:
        raise ContractError(
            "unsupported_version",
            f"unsupported schema_version: {version!r}. Supported versions: {sorted(SCHEMA_MAP)}"
        )

    expected_type = TYPE_MAP[version]
    if contract_type is not None:
        normalized_requested = contract_type.replace("-", "_")
        if normalized_requested != expected_type:
            raise ContractError(
                "invalid_contract",
                f"requested type '{contract_type}' does not match document schema_version '{version}'"
            )

    schema_file = SCHEMA_MAP[version]
    schema_path = SCHEMAS / schema_file
    if not schema_path.is_file():
        raise ContractError("invalid_contract", f"schema definition missing: {schema_file}")

    # Validate primary identifier format before general schema validation
    id_field_map = {
        "engagement": "engagement_id",
        "scenario": "scenario_id",
        "action_plan": "plan_id",
        "run_result": "result_id",
        "finding": "finding_id",
        "execution_authorization": "authorization_id",
    }
    primary_id_field = id_field_map.get(expected_type)
    if primary_id_field and primary_id_field in document:
        validate_identifier(document[primary_id_field], expected_type)

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        _check(document, schema)
    except EvidenceError as err:
        raise ContractError(err.code, f"schema validation failed: {err}") from err

    # Invariant validation per contract type
    if expected_type == "engagement":
        validate_identifier(document["engagement_id"], "engagement")
        t_start = timestamp(document["window"]["started_at"])
        t_end = timestamp(document["window"]["authorized_until_utc"])
        if t_end < t_start:
            raise ContractError("invalid_timestamp", "window.authorized_until_utc cannot precede window.started_at")

    elif expected_type == "scenario":
        validate_identifier(document["scenario_id"], "scenario")
        # Validate that family_id matches prefix pattern
        if not re.fullmatch(r"^COPS-[A-Z0-9_.-]+$", document["family_id"]):
            raise ContractError("malformed_identifier", f"invalid family_id: {document['family_id']}")

    elif expected_type == "action_plan":
        validate_identifier(document["plan_id"], "action_plan")
        validate_identifier(document["engagement_id"], "engagement")
        validate_identifier(document["scenario_id"], "scenario")

        # Security check: verify no plaintext credential leak in references
        for ref in document.get("credential_references", []):
            if any(secret_marker in ref.lower() for secret_marker in ("bearer ", "ghp_", "eyj", "pass")):
                raise ContractError("credential_leak_detected", "raw credential detected in credential_references")

        expected_digest = build_action_plan_digest(
            target=document["target"],
            specialist_id=document["specialist_id"],
            operations=document["operations"],
            limits=document["limits"],
            max_bytes=max_bytes,
        )
        if document["plan_digest"] != expected_digest:
            raise ContractError(
                "integrity_mismatch",
                f"plan_digest mismatch: expected {expected_digest}, got {document['plan_digest']}"
            )

    elif expected_type == "execution_authorization":
        validate_identifier(document["authorization_id"], "execution_authorization")
        validate_identifier(document["action_plan_id"], "action_plan")
        validate_identifier(document["engagement_id"], "engagement")

        t_issued = timestamp(document["issued_at"])
        t_auth_until = timestamp(document["authorized_until_utc"])
        if t_auth_until < t_issued:
            raise ContractError("invalid_timestamp", "authorized_until_utc cannot precede issued_at")

        # Verify signature_digest over payload
        payload = {
            "action_plan_id": document["action_plan_id"],
            "plan_digest": document["plan_digest"],
            "engagement_id": document["engagement_id"],
            "operator": document["operator"],
            "issued_at": document["issued_at"],
            "authorized_until_utc": document["authorized_until_utc"],
            "bound_parameters": document["bound_parameters"],
            "approval_mode": document["approval_mode"],
        }
        expected_sig = digest(payload, max_bytes=max_bytes)
        if document["signature_digest"] != expected_sig:
            raise ContractError(
                "integrity_mismatch",
                f"signature_digest mismatch: expected {expected_sig}, got {document['signature_digest']}"
            )

        if document.get("status") == "consumed":
            if not document.get("consumed_at") or not document.get("consumed_by_worker"):
                raise ContractError(
                    "missing_consumption_metadata",
                    "status 'consumed' requires consumed_at and consumed_by_worker"
                )

    elif expected_type == "run_result":
        validate_identifier(document["result_id"], "run_result")
        validate_identifier(document["plan_id"], "action_plan")
        validate_identifier(document["engagement_id"], "engagement")

        t_start = timestamp(document["started_at"])
        t_finish = timestamp(document["finished_at"])
        if t_finish < t_start:
            raise ContractError("invalid_timestamp", "finished_at cannot precede started_at")

        status = document["status"]
        if status not in RUN_RESULT_STATUSES:
            raise ContractError("invalid_contract", f"unknown run result status: {status}")

        # Representation of non-success results: MUST provide explicit reason
        if status != "success":
            reason = document.get("status_details", {}).get("reason")
            if not reason or not isinstance(reason, str) or not reason.strip():
                raise ContractError(
                    "missing_reason",
                    f"non-success status '{status}' requires an explicit, non-empty status_details.reason"
                )

    elif expected_type == "finding":
        validate_identifier(document["finding_id"], "finding")
        validate_identifier(document["engagement_id"], "engagement")
        validate_identifier(document["result_id"], "run_result")
        validate_identifier(document["scenario_id"], "scenario")

        # Provenance invariant: A verified finding MUST have at least one evidence reference
        if document["verification"] == "verified":
            evidence_refs = document.get("evidence_references", [])
            if not evidence_refs:
                raise ContractError(
                    "missing_evidence_reference",
                    "a verified finding must reference at least one evidence envelope record"
                )

    return document
