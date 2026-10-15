"""Acceptance steps for evidence-bounded offline engagement reports."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.contracts.lifecycle import ContractError
from cops.contracts.validation import build_action_plan_digest, validate_contract
from cops.evidence.canonical import digest
from cops.reporting.assessment import ReportError, build_assessment_report

scenarios("../../specs/features/engagement_reporting.feature")

FIXTURE = Path(__file__).resolve().parents[2] / "cops/contracts/fixtures/valid_assessment_input.json"


@pytest.fixture
def report_ctx():
    return {"bundle": None, "report": None, "error": None}


@given("a valid offline assessment bundle")
def valid_bundle(report_ctx):
    report_ctx["bundle"] = json.loads(FIXTURE.read_text(encoding="utf-8"))


@given("its finding is a scanner assertion")
def scanner_assertion(report_ctx):
    report_ctx["bundle"]["finding_contexts"][0]["kind"] = "scanner_assertion"


@given("its finding is a scanner assertion with an unverified observation")
def scanner_with_unverified_observation(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    observation = deepcopy(bundle["findings"][0])
    observation["finding_id"] = "find-unverified-bdd-001"
    observation["verification"] = "unverified"
    observation["evidence_references"] = []
    bundle["findings"].append(observation)
    context = deepcopy(bundle["finding_contexts"][0])
    context["finding_id"] = observation["finding_id"]
    context["kind"] = "observed_behavior"
    bundle["finding_contexts"].append(context)


@given("its finding has no result identifier")
def missing_result_identifier(report_ctx):
    del report_ctx["bundle"]["findings"][0]["result_id"]


@given("its live observation precedes the run window")
def live_observation_before_run(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["mode"] = "live"
    bundle["action_plans"][0]["status"] = "fulfilled"
    bundle["coverage"][0]["mode"] = "live"
    bundle["evidence_envelopes"][0]["observed"] = {
        "at": "2026-10-02T10:04:59Z",
        "unknown_reason": None,
    }
    envelope = bundle["evidence_envelopes"][0]
    envelope["content_hash"] = digest({key: value for key, value in envelope.items() if key != "content_hash"})


@given("its finding also affects a second asset without evidence")
def second_asset_without_evidence(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["scope"]["excluded_targets"] = []
    plan = bundle["action_plans"][0]
    plan["target"] = "10.0.0.0/24"
    plan["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in plan.items() if key not in {"status", "plan_digest"}}
    )
    bundle["finding_contexts"][0]["affected_assets"].append("10.0.0.6")
    bundle["coverage"].append({**bundle["coverage"][0], "target": "10.0.0.6"})


@given("its attack path has a supported prerequisite")
def attack_path_prerequisite(report_ctx):
    bundle = report_ctx["bundle"]
    context = bundle["finding_contexts"][0]
    context["kind"] = "reproduced_attack_path"
    context["attack_path_dependencies"] = ["find-prerequisite-001"]
    prerequisite = deepcopy(bundle["findings"][0])
    prerequisite["finding_id"] = "find-prerequisite-001"
    bundle["findings"].append(prerequisite)
    prerequisite_context = deepcopy(context)
    prerequisite_context.update(
        {"finding_id": "find-prerequisite-001", "kind": "observed_behavior", "attack_path_dependencies": []}
    )
    bundle["finding_contexts"].append(prerequisite_context)


@when("the assessment report is built")
def build_report(report_ctx):
    try:
        report_ctx["report"] = build_assessment_report(report_ctx["bundle"])
    except ReportError as error:
        report_ctx["error"] = error


@when("the saved finding is changed to unsupported recorded evidence")
def unsupported_recorded_evidence(report_ctx):
    finding = report_ctx["report"]["findings"][0]
    finding["assessment_status"] = "partial"
    finding["evidence_references"] = []


@when("the saved scanner coverage is changed to assessed")
def unsupported_scanner_coverage(report_ctx):
    report_ctx["report"]["coverage"][0]["status"] = "assessed"


@when("the saved prerequisite points back to the attack path")
def cyclic_saved_prerequisite(report_ctx):
    report_ctx["report"]["findings"][1]["attack_path_dependencies"] = ["find-open-port-http-80"]


@then("its coverage and finding are assessed")
def assessed_claims(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["status"] == "assessed"
    assert report_ctx["report"]["findings"][0]["assessment_status"] == "assessed"


@then("its coverage is partial")
def partial_coverage(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["status"] == "partial"


@then("its live coverage and finding are not assessed")
def live_observation_not_assessed(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["provenance"] == "live_unvalidated"
    assert report_ctx["report"]["coverage"][0]["status"] == "not_assessed"
    assert report_ctx["report"]["findings"][0]["assessment_status"] == "not_assessed"


@then("the second asset is not assessed and the finding is partial")
def second_asset_not_assessed(report_ctx):
    assert report_ctx["error"] is None
    assert [row["status"] for row in report_ctx["report"]["coverage"]] == ["assessed", "not_assessed"]
    finding = report_ctx["report"]["findings"][0]
    assert finding["assessment_status"] == "partial"
    assert finding["limitations"] == ["Not assessed for assets: 10.0.0.6"]


@then("its attack path and prerequisite validate")
def supported_attack_path(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["findings"][0]["attack_path_dependencies"] == ["find-prerequisite-001"]
    validate_contract(report_ctx["report"], "assessment_report")


@then("the saved assessment report validates")
def valid_saved_report(report_ctx):
    validate_contract(report_ctx["report"], "assessment_report")


@then("report building fails with an invalid finding contract")
def invalid_finding(report_ctx):
    assert isinstance(report_ctx["error"], ReportError)
    assert "invalid finding contract" in str(report_ctx["error"])


@then("the saved assessment report is rejected")
def invalid_saved_report(report_ctx):
    with pytest.raises(ContractError):
        validate_contract(report_ctx["report"], "assessment_report")
