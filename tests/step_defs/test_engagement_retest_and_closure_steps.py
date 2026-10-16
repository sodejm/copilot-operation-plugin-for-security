"""Acceptance steps for evidence-bounded engagement retest review."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.evidence.canonical import digest
from cops.reporting.assessment import build_assessment_report
from cops.reporting.retest import build_retest_report

scenarios("../../specs/features/engagement-retest-and-closure.feature")

FIXTURE = Path(__file__).resolve().parents[2] / "cops/contracts/fixtures/valid_assessment_input.json"


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
        "unresolved_effects": [
            {"effect_id": "artifact-1", "resource_type": "file", "target": "lab-host", "reason": "pending"}
        ]
        if status == "failed"
        else [],
    }
    receipt["evidence_hash"] = digest(
        {
            key: receipt[key]
            for key in (
                "receipt_id",
                "plan_id",
                "engagement_id",
                "worker_identity",
                "cleaned_effects",
                "unresolved_effects",
            )
        }
    )
    return receipt


def _input() -> dict:
    source = json.loads(FIXTURE.read_text(encoding="utf-8"))
    baseline = build_assessment_report(source)
    retest = deepcopy(baseline)
    retest["report_id"] = "report-retest-001"
    retest["generated_at"] = "2026-10-03T12:00:00Z"
    retest_record = "e" * 64
    retest["coverage"][0]["evidence_records"] = [retest_record]
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
        "checks": [
            {
                "finding_id": "find-open-port-http-80",
                "asset": "10.0.0.5",
                "retest_asset": "10.0.0.5",
                "outcome": "absent",
                "evidence_records": [retest_record],
            }
        ],
    }


@pytest.fixture
def retest_ctx():
    return {"bundle": None, "reports": []}


@given("a baseline finding and a later assessed retest of the same engagement and exact asset")
@given("a baseline finding")
@given("an otherwise supported candidate_fixed finding")
@given("an assessed live retest using the baseline plan ID")
def baseline_retest(retest_ctx):
    retest_ctx["bundle"] = _input()


@when("an absent observation references retest evidence for that scenario and asset")
def compare_supported_absence(retest_ctx):
    retest_ctx["reports"] = [build_retest_report(retest_ctx["bundle"])]


@when("the retest target is inaccessible or has a different identity")
def compare_inaccessible_and_changed(retest_ctx):
    inaccessible = deepcopy(retest_ctx["bundle"])
    inaccessible["checks"][0]["outcome"] = "inaccessible"
    changed = deepcopy(retest_ctx["bundle"])
    changed["checks"][0]["retest_asset"] = "10.0.0.6"
    retest_ctx["reports"] = [build_retest_report(inaccessible), build_retest_report(changed)]


@when("cleanup remains unresolved or the live retest plan differs from the baseline plan")
def compare_cleanup_and_changed_plan(retest_ctx):
    unresolved = deepcopy(retest_ctx["bundle"])
    unresolved["cleanup_receipts"] = [_receipt("plan-scan-10-0-0-5", "failed", status="failed")]
    changed = deepcopy(retest_ctx["bundle"])
    changed["retest_report"]["coverage"][0]["mode"] = "live"
    changed["retest_report"]["coverage"][0]["provenance"] = "live_validated"
    changed["retest_plan_id"] = "plan-retest-new-001"
    changed["cleanup_receipts"].append(_receipt("plan-retest-new-001", "new"))
    retest_ctx["reports"] = [build_retest_report(unresolved), build_retest_report(changed)]


@when("the comparison finds an absent observation")
def compare_live_absence(retest_ctx):
    bundle = retest_ctx["bundle"]
    bundle["retest_report"]["coverage"][0]["mode"] = "live"
    bundle["retest_report"]["coverage"][0]["provenance"] = "live_validated"
    retest_ctx["reports"] = [build_retest_report(bundle)]


@then("the comparison labels the finding candidate_fixed and blocks closure pending independent verification")
def supported_absence_is_review_only(retest_ctx):
    report = retest_ctx["reports"][0]
    assert report["results"][0]["status"] == "candidate_fixed"
    assert report["closure_status"] == "blocked"
    assert {"source_verification_required", "owner_verification_required", "cleanup_verification_required"} <= set(
        report["closure_gates"]
    )


@then("the comparison does not label the finding candidate_fixed")
def no_fixed_label(retest_ctx):
    assert all(report["results"][0]["status"] != "candidate_fixed" for report in retest_ctx["reports"])


@then("the comparison requires further review and never closes the engagement")
def cleanup_and_plan_require_review(retest_ctx):
    unresolved, changed = retest_ctx["reports"]
    assert unresolved["closure_status"] == changed["closure_status"] == "blocked"
    assert "cleanup_incomplete" in unresolved["closure_gates"]
    assert "fresh_authorization_required" in changed["closure_gates"]


@then("it still requires verification of the run authority and cleanup binding")
def live_retest_requires_bindings(retest_ctx):
    gates = retest_ctx["reports"][0]["closure_gates"]
    assert "live_authority_binding_required" in gates
    assert "cleanup_run_binding_required" in gates
