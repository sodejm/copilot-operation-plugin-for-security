"""BDD steps for the offline Windows privilege-boundary contract."""

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

scenarios("../../specs/features/host_windows_privilege_boundaries.feature")


@pytest.fixture
def context() -> dict:
    return {}


def fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / f"host_windows_{name}_v1.json").read_text())


@given("the vulnerable synthetic Windows host fixture")
def vulnerable(context):
    context["payload"] = fixture("vulnerable")


@given("the protected and remediated synthetic Windows host fixtures")
def protected_remediated(context):
    context["payloads"] = [fixture("protected"), fixture("remediated")]


@given("a vulnerable synthetic Windows host fixture with an unmatched build")
def unmatched_build(context):
    context["payload"] = fixture("vulnerable")
    context["payload"]["host"]["os_build"] = "10.0.10000"


@given("a vulnerable synthetic Windows host fixture without cleanup assertion")
def no_cleanup(context):
    context["payload"] = fixture("vulnerable")
    context["payload"]["observations"][0]["canary"]["cleanup_verified"] = False


@when("the Windows host importer assesses it")
def assess_one(context):
    context["report"] = assess_document(context["payload"])


@when("the Windows host importer assesses both")
def assess_both(context):
    context["reports"] = [assess_document(payload) for payload in context["payloads"]]


@when("the Windows host importer attempts to assess it")
def attempts_assessment(context):
    assert "payload" in context


@then("the report identifies a source-reported canary crossing")
def reported_crossing(context):
    assert context["report"]["source"]["kind"] == "synthetic_lab"
    assert context["report"]["observations"][0]["classification"] == "reported_canary_crossing"


@then("all seven Windows surfaces have explicit coverage states")
def coverage(context):
    assert len(context["report"]["coverage"]) == 7


@then("the selected check records build, architecture, token, and protections")
def prerequisites(context):
    result = context["report"]["observations"][0]
    assert result["decision"] == "selected"
    assert set(result["requirements"]) == {"build_min", "build_max", "architecture", "token", "protections"}
    assert context["report"]["host"]["os_build"] == "10.0.19045"


@then("both reports identify source-reported blocked canaries")
def reported_blocked(context):
    assert all(
        report["observations"][0]["classification"] == "reported_canary_blocked" for report in context["reports"]
    )


@then("the Windows observation is inapplicable without a success classification")
def no_success(context):
    result = context["report"]["observations"][0]
    assert result["decision"] == "inapplicable"
    assert result["classification"] == "not_evaluated"


@then("the Windows importer rejects the incomplete canary report")
def rejects(context):
    with pytest.raises(ContractError):
        assess_document(context["payload"])
