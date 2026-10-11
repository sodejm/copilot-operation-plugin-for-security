"""BDD steps for the offline Linux privilege-boundary contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "plugins" / "offensive-security" / "host-assessment-workbench"
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import ContractError, assess_document  # noqa: E402

scenarios("../../specs/features/host_linux_privilege_boundaries.feature")


@pytest.fixture
def context() -> dict:
    return {}


def fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / f"host_linux_{name}_v1.json").read_text())


@given("the positive synthetic Linux host fixture")
def positive(context):
    context["payload"] = fixture("positive")


@given("the negative and fixed synthetic Linux host fixtures")
def negative_fixed(context):
    context["payloads"] = [fixture("negative"), fixture("fixed")]


@given("a positive synthetic Linux host fixture with an unmatched namespace requirement")
def unmatched(context):
    context["payload"] = fixture("positive")
    context["payload"]["observations"][0]["requirements"]["namespace"] = "container"


@given("a positive synthetic Linux host fixture without verified cleanup")
def no_cleanup(context):
    context["payload"] = fixture("positive")
    context["payload"]["observations"][0]["canary"]["cleanup_verified"] = False


@when("the host privilege-boundary importer assesses it")
def assess_one(context):
    context["report"] = assess_document(context["payload"])


@when("the host privilege-boundary importer assesses both")
def assess_both(context):
    context["reports"] = [assess_document(payload) for payload in context["payloads"]]


@when("the host privilege-boundary importer attempts to assess it")
def attempts_assessment(context):
    assert "payload" in context


@then("the report identifies a reported canary crossing from synthetic evidence")
def reported_crossing(context):
    assert context["report"]["source"]["kind"] == "synthetic_lab"
    assert context["report"]["observations"][0]["classification"] == "reported_canary_crossing"


@then("all eight Linux surfaces have explicit coverage states")
def coverage(context):
    assert len(context["report"]["coverage"]) == 8


@then("the selected check records its kernel, distribution version, namespace, and protections")
def prerequisites(context):
    requirements = context["report"]["observations"][0]["requirements"]
    assert set(requirements) == {"kernel_release", "distribution_id", "distribution_version", "namespace", "protections"}
    assert requirements["distribution_version"] == "24.04"


@then("both reports identify reported blocked canaries")
def reported_blocked(context):
    assert all(report["observations"][0]["classification"] == "reported_canary_blocked" for report in context["reports"])


@then("the observation is inapplicable and has no success classification")
def no_success(context):
    result = context["report"]["observations"][0]
    assert result["decision"] == "inapplicable"
    assert result["classification"] == "not_evaluated"


@then("the importer rejects the incomplete canary report")
def rejects(context):
    with pytest.raises(ContractError):
        assess_document(context["payload"])
