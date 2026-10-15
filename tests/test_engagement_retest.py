"""Offline retest conclusions require matched evidence and explicit closure gates."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from cops.contracts.lifecycle import ContractError
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import digest
from cops.cli import command_contract_validate
from cops.reporting.assessment import ReportError, build_assessment_report
from cops.reporting.cli import command_engagement_retest
from cops.reporting.retest import build_retest_report, render_retest_markdown, verify_retest_report_derivation

FIXTURE = Path(__file__).resolve().parents[1] / "cops" / "contracts" / "fixtures" / "valid_assessment_input.json"


def _receipt(plan_id: str, suffix: str, *, status: str = "not_required") -> dict:
    receipt = {
        "schema_version": "cops.cleanup-receipt/v1",
        "receipt_id": f"cln-retest-{suffix}",
        "plan_id": plan_id,
        "engagement_id": "eng-secops-20261002",
        "worker_identity": "worker-1",
        "status": status,
        "created_at": "2026-10-03T12:00:00Z",
        "completed_at": "2026-10-03T12:01:00Z",
        "cleaned_effects": [],
        "unresolved_effects": [{"effect_id": "artifact-1", "resource_type": "file", "target": "lab-host",
                                "reason": "cleanup pending"}] if status == "failed" else [],
    }
    receipt["evidence_hash"] = digest({key: receipt[key] for key in (
        "receipt_id", "plan_id", "engagement_id", "worker_identity", "cleaned_effects", "unresolved_effects"
    )})
    return receipt


def _input(*, present: bool = False) -> dict:
    source = json.loads(FIXTURE.read_text(encoding="utf-8"))
    baseline = build_assessment_report(source)
    retest = deepcopy(baseline)
    retest["report_id"] = "report-retest-001"
    retest["generated_at"] = "2026-10-03T12:00:00Z"
    retest_record = "e" * 64
    retest["coverage"][0]["evidence_records"] = [retest_record]
    if present:
        retest["findings"][0]["evidence_references"] = [retest_record]
    else:
        retest["findings"] = []
    return {
        "schema_version": "cops.retest-input/v1",
        "retest_id": "retest-service-001",
        "generated_at": "2026-10-03T13:00:00Z",
        "baseline_report": baseline,
        "retest_report": retest,
        "baseline_plan_id": "plan-scan-10-0-0-5",
        "retest_plan_id": "plan-scan-10-0-0-5",
        "owner_reference": "owner-ticket-123",
        "owner_acknowledged": True,
        "residual_risks": [],
        "cleanup_receipts": [_receipt("plan-scan-10-0-0-5", "same")],
        "checks": [{
            "finding_id": "find-open-port-http-80", "asset": "10.0.0.5", "retest_asset": "10.0.0.5",
            "outcome": "present" if present else "absent", "evidence_records": [retest_record],
        }],
    }


def test_supported_absence_is_only_a_candidate_and_blocks_closure():
    bundle = _input()
    validate_contract(bundle, "retest_input")
    report = build_retest_report(bundle)
    validate_contract(report, "retest_report")
    assert report["results"][0]["status"] == "candidate_fixed"
    assert report["closure_status"] == "blocked"
    assert set(report["closure_gates"]) == {
        "source_verification_required", "owner_verification_required", "cleanup_verification_required"
    }
    assert "does not close" in render_retest_markdown(report)


def test_supported_present_remains_vulnerable():
    report = build_retest_report(_input(present=True))
    assert report["results"][0]["status"] == "candidate_still_vulnerable"
    assert "candidate_still_vulnerable" in report["closure_gates"]


@pytest.mark.parametrize("outcome,status", [
    ("inaccessible", "inaccessible"), ("blocked", "blocked"), ("not_assessed", "not_assessed")
])
def test_unassessed_outcome_never_becomes_fixed(outcome: str, status: str):
    bundle = _input()
    bundle["checks"][0]["outcome"] = outcome
    assert build_retest_report(bundle)["results"][0]["status"] == status


def test_changed_asset_and_missing_check_remain_open():
    bundle = _input()
    bundle["checks"][0]["retest_asset"] = "10.0.0.6"
    assert build_retest_report(bundle)["results"][0]["status"] == "identity_changed"
    bundle["checks"] = []
    assert build_retest_report(bundle)["results"][0]["status"] == "not_assessed"


def test_cleanup_ownership_and_changed_live_plan_gate_review():
    bundle = _input()
    bundle["owner_acknowledged"] = False
    bundle["cleanup_receipts"][0] = _receipt("plan-scan-10-0-0-5", "same", status="failed")
    bundle["retest_report"]["coverage"][0]["mode"] = "live"
    bundle["retest_report"]["coverage"][0]["provenance"] = "live_validated"
    bundle["retest_plan_id"] = "plan-retest-new-001"
    bundle["cleanup_receipts"].append(_receipt("plan-retest-new-001", "new"))
    report = build_retest_report(bundle)
    assert report["closure_status"] == "blocked"
    assert set(report["closure_gates"]) == {
        "owner_acknowledgement_required", "cleanup_incomplete", "fresh_authorization_required",
        "source_verification_required", "owner_verification_required", "cleanup_verification_required",
        "live_authority_binding_required", "cleanup_run_binding_required",
    }
    assert report["review_context"]["cleanup_receipts"][0]["unresolved_effects"][0]["effect_id"] == "artifact-1"
    assert "artifact-1" in render_retest_markdown(report)


def test_residual_risk_is_visible_and_blocks_review():
    bundle = _input()
    bundle["residual_risks"] = ["A scoped asset still needs a separate review."]
    report = build_retest_report(bundle)
    assert "residual_risk_review" in report["closure_gates"]
    assert report["review_context"]["residual_risks"] == bundle["residual_risks"]
    assert bundle["residual_risks"][0] in render_retest_markdown(report)
    report["closure_gates"] = []
    report["closure_status"] = "ready_for_review"
    with pytest.raises(ContractError):
        validate_contract(report, "retest_report")


def test_absence_with_conflicting_finding_or_old_evidence_is_gap():
    bundle = _input(present=True)
    bundle["checks"][0]["outcome"] = "absent"
    assert build_retest_report(bundle)["results"][0]["status"] == "evidence_gap"


def test_unrelated_new_record_cannot_freshen_old_coverage():
    bundle = _input()
    old_record = bundle["baseline_report"]["findings"][0]["evidence_references"][0]
    new_record = bundle["checks"][0]["evidence_records"][0]
    bundle["checks"][0]["evidence_records"] = [old_record, new_record]
    bundle["retest_report"]["coverage"][0]["evidence_records"] = [old_record]
    assert build_retest_report(bundle)["results"][0]["status"] == "evidence_gap"

    bundle = _input(present=True)
    old_record = bundle["baseline_report"]["findings"][0]["evidence_references"][0]
    new_record = bundle["checks"][0]["evidence_records"][0]
    bundle["checks"][0]["evidence_records"] = [old_record, new_record]
    bundle["retest_report"]["coverage"][0]["evidence_records"] = [old_record, new_record]
    bundle["retest_report"]["findings"][0]["evidence_references"] = [old_record]
    assert build_retest_report(bundle)["results"][0]["status"] == "evidence_gap"


def test_record_from_other_baseline_coverage_cannot_prove_fix():
    bundle = _input()
    reused_record = "d" * 64
    bundle["baseline_report"]["coverage"][0]["evidence_records"].append(reused_record)
    bundle["retest_report"]["coverage"][0]["evidence_records"] = [reused_record]
    bundle["checks"][0]["evidence_records"] = [reused_record]
    assert build_retest_report(bundle)["results"][0]["status"] == "evidence_gap"


def test_broad_coverage_cannot_prove_exact_asset_absence():
    bundle = _input()
    bundle["retest_report"]["coverage"][0]["target"] = "10.0.0.0/24"
    with pytest.raises(ReportError, match="invalid retest input"):
        build_retest_report(bundle)


def test_saved_report_rejects_duplicate_or_unsubstantiated_conclusions():
    report = build_retest_report(_input())
    report["results"].append(deepcopy(report["results"][0]))
    with pytest.raises(ContractError, match="duplicate retest result"):
        validate_contract(report, "retest_report")

    report = build_retest_report(_input())
    report["results"][0]["evidence_records"] = []
    with pytest.raises(ContractError, match="requires evidence"):
        validate_contract(report, "retest_report")

    report = build_retest_report(_input(present=True))
    report["closure_gates"] = []
    with pytest.raises(ContractError, match="omits closure review gate"):
        validate_contract(report, "retest_report")
    bundle = _input()
    old_record = bundle["baseline_report"]["findings"][0]["evidence_references"][0]
    bundle["retest_report"]["coverage"][0]["evidence_records"] = [old_record]
    bundle["checks"][0]["evidence_records"] = [old_record]
    assert build_retest_report(bundle)["results"][0]["status"] == "evidence_gap"


def test_tampered_receipt_and_cross_engagement_are_rejected():
    bundle = _input()
    bundle["cleanup_receipts"][0]["worker_identity"] = "changed"
    with pytest.raises(ContractError, match="digest mismatch"):
        validate_contract(bundle, "retest_input")
    bundle = _input()
    bundle["cleanup_receipts"][0]["status"] = "completed"
    with pytest.raises(ContractError, match="status disagrees"):
        validate_contract(bundle, "retest_input")
    bundle = _input()
    bundle["retest_report"]["engagement_id"] = "eng-other-0001"
    with pytest.raises(ContractError, match="engagement identities differ"):
        validate_contract(bundle, "retest_input")


def test_cli_writes_private_new_files_without_overwrite(tmp_path: Path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(_input()), encoding="utf-8")
    json_output, markdown_output = tmp_path / "report.json", tmp_path / "report.md"
    args = SimpleNamespace(input=source, json_output=json_output, markdown_output=markdown_output)
    assert command_engagement_retest(args) == 0
    assert json_output.stat().st_mode & 0o777 == 0o600
    assert markdown_output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ReportError, match="already exists"):
        command_engagement_retest(args)


def test_same_plan_live_retest_still_needs_run_authority_and_cleanup_binding():
    bundle = _input()
    bundle["retest_report"]["coverage"][0]["mode"] = "live"
    bundle["retest_report"]["coverage"][0]["provenance"] = "live_validated"
    report = build_retest_report(bundle)
    assert "live_authority_binding_required" in report["closure_gates"]
    assert "cleanup_run_binding_required" in report["closure_gates"]
    assert "fresh_authorization_required" not in report["closure_gates"]


def test_saved_report_derivation_catches_tampering(tmp_path: Path, capsys):
    bundle = _input()
    report = build_retest_report(bundle)
    verify_retest_report_derivation(report, bundle)
    source_path, report_path = tmp_path / "input.json", tmp_path / "report.json"
    source_path.write_text(json.dumps(bundle), encoding="utf-8")
    report_path.write_text(json.dumps(report), encoding="utf-8")
    assert command_contract_validate(report_path, "retest_report", source_path) == 0
    assert "authenticity" in capsys.readouterr().out
    report["results"][0]["reason"] = "Unsupported assertion"
    validate_contract(report, "retest_report")
    report_path.write_text(json.dumps(report), encoding="utf-8")
    assert command_contract_validate(report_path, "retest_report", source_path) == 1
    assert "differs from supplied input" in capsys.readouterr().err
