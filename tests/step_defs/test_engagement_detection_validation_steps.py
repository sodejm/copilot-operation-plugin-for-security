"""Executable acceptance scenarios for action-linked detection outcomes."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.reporting.assessment import ReportError
from cops.reporting.detection import build_detection_report

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_engagement_detection_validation import bundle_for, record  # noqa: E402

scenarios("../../specs/features/engagement_detection_validation.feature")


@pytest.fixture
def context():
    return {}


@given("a completed action with a linked telemetry record and alert")
def linked_alert(context):
    context["bundle"] = bundle_for("detected")


@given("a completed action with telemetry and a covering zero-result search")
def covering_search(context):
    context["bundle"] = bundle_for("missed")


@given("a completed action with telemetry and an incomplete search")
def incomplete_search(context):
    context["bundle"] = bundle_for("ambiguous")


@given("an action without an execution observation")
def missing_execution(context):
    context["bundle"] = bundle_for("unavailable")


@given("a completed action with evidence from another tenant")
def alien_evidence(context):
    bundle = bundle_for("detected")
    bundle["evidence_envelopes"][0] = record(bundle["evidence_envelopes"][0]["payload"], tenant="tenant-2")
    context["bundle"] = bundle


@when("the offline detection report is built")
def build_report(context):
    context["report"] = build_detection_report(context["bundle"])


@when("the offline detection report is attempted", target_fixture="rejected_report")
def reject_report(context):
    with pytest.raises(ReportError):
        build_detection_report(context["bundle"])
    return True


@then("the measured status is detected")
def detected(context):
    assert context["report"]["checks"][0]["status"] == "detected"


@then("the measured status is missed")
def missed(context):
    assert context["report"]["checks"][0]["status"] == "missed"


@then("the measured status is ambiguous")
def ambiguous(context):
    assert context["report"]["checks"][0]["status"] == "ambiguous"


@then("the measured status is unavailable")
def unavailable(context):
    assert context["report"]["checks"][0]["status"] == "unavailable"


@then("the offline detection report is rejected")
def rejected(rejected_report):
    assert rejected_report is True
