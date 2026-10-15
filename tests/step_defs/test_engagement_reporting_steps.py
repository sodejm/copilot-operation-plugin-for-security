"""Acceptance steps for evidence-bounded offline engagement reports."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.contracts.lifecycle import ContractError
from cops.contracts.validation import validate_contract
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


@then("its coverage and finding are assessed")
def assessed_claims(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["status"] == "assessed"
    assert report_ctx["report"]["findings"][0]["assessment_status"] == "assessed"


@then("its coverage is partial")
def partial_coverage(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["status"] == "partial"


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
