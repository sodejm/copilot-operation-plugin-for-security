"""Behavioral unit tests for COPS operational and engagement contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cops.contracts import (
    ActionPlan,
    ContractError,
    Engagement,
    Finding,
    RunResult,
    build_action_plan_digest,
    evaluate_run_result,
    validate_contract,
    validate_identifier,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "cops" / "contracts" / "fixtures"


def _cleanup_receipt_payload(
    schema_version: str = "cops.cleanup-receipt/v1",
    *,
    quarantine_target: str | None = None,
) -> dict[str, object]:
    unresolved_effect: dict[str, object] = {
        "effect_id": "effect-contract-test",
        "resource_type": "directory",
        "target": "/tmp/contract-test",
        "reason": "preserved for operator reconciliation",
    }
    if quarantine_target is not None:
        unresolved_effect["quarantine_target"] = quarantine_target
    return {
        "schema_version": schema_version,
        "receipt_id": "cln-contract-test",
        "plan_id": "plan-contract-test",
        "engagement_id": "eng-contract-test",
        "worker_identity": "worker-contract-test",
        "status": "failed",
        "created_at": "2026-10-09T12:00:00Z",
        "completed_at": "2026-10-09T12:00:01Z",
        "cleaned_effects": [],
        "unresolved_effects": [unresolved_effect],
        "evidence_hash": "0" * 64,
    }


def test_cleanup_receipt_v1_remains_strict_and_backward_compatible():
    validate_contract(_cleanup_receipt_payload(), "cleanup_receipt")

    with pytest.raises(ContractError):
        validate_contract(
            _cleanup_receipt_payload(quarantine_target="/tmp/quarantine"),
            "cleanup_receipt",
        )


def test_cleanup_receipt_v2_accepts_quarantine_location():
    validate_contract(
        _cleanup_receipt_payload(
            "cops.cleanup-receipt/v2",
            quarantine_target="/tmp/quarantine",
        ),
        "cleanup_receipt",
    )


def test_valid_fixtures_pass():
    valid_files = [
        "valid_engagement.json",
        "valid_scenario.json",
        "valid_action_plan.json",
        "valid_run_result_success.json",
        "valid_run_result_partial.json",
        "valid_run_result_failed.json",
        "valid_finding_verified.json",
    ]
    for filename in valid_files:
        path = FIXTURES_DIR / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        validated = validate_contract(data)
        assert validated["schema_version"] == data["schema_version"]


def test_invalid_fixtures_fail_with_expected_codes():
    cases = [
        ("invalid_engagement_time_window.json", "invalid_timestamp"),
        ("invalid_action_plan_tampered_digest.json", "integrity_mismatch"),
        ("invalid_action_plan_credential_leak.json", "credential_leak_detected"),
        ("invalid_run_result_silent_success.json", "missing_reason"),
        ("invalid_finding_verified_missing_evidence.json", "missing_evidence_reference"),
        ("invalid_schema_version.json", "unsupported_version"),
        ("malformed_identifier.json", "malformed_identifier"),
    ]
    for filename, expected_code in cases:
        path = FIXTURES_DIR / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        with pytest.raises(ContractError) as ctx:
            validate_contract(data)
        assert ctx.value.code == expected_code, f"File {filename} raised {ctx.value.code}, expected {expected_code}"


def test_engagement_lifecycle_transitions():
    data = json.loads((FIXTURES_DIR / "valid_engagement.json").read_text(encoding="utf-8"))
    eng = Engagement.from_dict(data)
    assert eng.status == "planned"

    eng.transition_to("active")
    assert eng.status == "active"

    eng.transition_to("completed")
    assert eng.status == "completed"

    # Completed is terminal
    with pytest.raises(ContractError) as ctx:
        eng.transition_to("active")
    assert ctx.value.code == "illegal_transition"


def test_action_plan_lifecycle_transitions():
    data = json.loads((FIXTURES_DIR / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan = ActionPlan.from_dict(data)
    assert plan.status == "draft"

    plan.transition_to("pending_approval")
    assert plan.status == "pending_approval"

    plan.transition_to("approved")
    assert plan.status == "approved"

    plan.transition_to("executing")
    assert plan.status == "executing"

    plan.transition_to("fulfilled")
    assert plan.status == "fulfilled"

    # Fulfilled is terminal
    with pytest.raises(ContractError) as ctx:
        plan.transition_to("executing")
    assert ctx.value.code == "illegal_transition"


def test_unapproved_action_plan_cannot_execute():
    data = json.loads((FIXTURES_DIR / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan = ActionPlan.from_dict(data)
    with pytest.raises(ContractError) as ctx:
        plan.transition_to("executing")
    assert ctx.value.code == "illegal_transition"


def test_rejected_action_plan_cannot_execute():
    data = json.loads((FIXTURES_DIR / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan = ActionPlan.from_dict(data)
    plan.transition_to("pending_approval")
    plan.transition_to("rejected")
    with pytest.raises(ContractError) as ctx:
        plan.transition_to("executing")
    assert ctx.value.code == "illegal_transition"


@pytest.mark.parametrize("status", ["partial", "cancelled", "failed", "uncertain", "not_assessed"])
def test_non_success_run_results_never_evaluate_as_successful(status):
    data = json.loads((FIXTURES_DIR / "valid_run_result_success.json").read_text(encoding="utf-8"))
    data["status"] = status
    data["status_details"] = {"summary": "Execution stopped", "reason": f"status_was_{status}"}
    res = RunResult.from_dict(data)
    assert res.is_successful() is False
    assert evaluate_run_result(data) is False


def test_run_result_missing_reason_fails():
    data = json.loads((FIXTURES_DIR / "valid_run_result_success.json").read_text(encoding="utf-8"))
    data["status"] = "partial"
    data["status_details"] = {"summary": "Incomplete"}
    with pytest.raises(ContractError) as ctx:
        validate_contract(data)
    assert ctx.value.code == "missing_reason"


def test_finding_requires_evidence_when_verified():
    data = json.loads((FIXTURES_DIR / "valid_finding_verified.json").read_text(encoding="utf-8"))
    find = Finding.from_dict(data)
    assert find.verification == "verified"
    assert len(find.evidence_references) > 0

    data["evidence_references"] = []
    with pytest.raises(ContractError) as ctx:
        validate_contract(data)
    assert ctx.value.code == "missing_evidence_reference"


def test_action_plan_digest_computation():
    snapshot = {
        "schema_version": "cops.action-plan/v1",
        "plan_id": "plan-digest-test",
        "engagement_id": "eng-digest-test",
        "scenario_id": "COPS-E03.01-S01",
        "target": "10.0.0.1",
        "specialist_id": "cops-network-specialist",
        "operations": [
            {
                "step_id": "s1",
                "tool": "python3",
                "tool_version": "3.11.9",
                "action": "test",
                "arguments": {},
                "timeout_seconds": 10,
            }
        ],
        "limits": {
            "max_duration_seconds": 60,
            "max_output_bytes": 1024,
            "egress_allowed": False,
        },
        "credential_references": [],
        "created_at": "2026-10-02T10:00:00Z",
        "platform_prerequisites": ["linux"],
        "batch": {"mode": "sequential", "max_operations": 1, "fail_fast": True},
    }
    digest1 = build_action_plan_digest(snapshot=snapshot)
    digest2 = build_action_plan_digest(snapshot=snapshot)
    assert digest1 == digest2
    assert len(digest1) == 64


def test_identifier_patterns():
    validate_identifier("eng-test-01", "engagement")
    validate_identifier("scen-k8s-pod-escape", "scenario")
    validate_identifier("COPS-E01.03-S01", "scenario")
    validate_identifier("plan-auth-check-01", "action_plan")
    validate_identifier("res-test-output-01", "run_result")
    validate_identifier("find-port-80-exposed", "finding")

    with pytest.raises(ContractError) as ctx:
        validate_identifier("INVALID!ID", "engagement")
    assert ctx.value.code == "malformed_identifier"
