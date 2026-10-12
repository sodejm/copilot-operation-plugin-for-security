"""Executable acceptance criteria for advisory model routing."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.routing.model_advisor import advise_models, parse_catalog

scenarios("../../specs/features/model_effort_routing.feature")


@pytest.fixture
def context():
    return {}


@given("a fresh catalog with an efficient model and a security flagship")
def fresh_catalog(context):
    context["catalog"] = parse_catalog(
        {
            "schema_version": "cops.model-catalog/v1",
            "source": "test host discovery",
            "observed_at": datetime.now(UTC).isoformat(),
            "models": [
                {
                    "id": "test-efficient",
                    "family": "General",
                    "tier": "efficient",
                    "capabilities": ["general"],
                    "available": True,
                    "access": "granted",
                    "efforts": ["low", "medium"],
                    "preference": 0,
                },
                {
                    "id": "test-security",
                    "family": "Daybreak",
                    "tier": "flagship",
                    "capabilities": ["security"],
                    "available": True,
                    "access": "granted",
                    "efforts": ["low", "medium", "high"],
                    "preference": 1,
                },
            ],
        }
    )


@given("a fresh catalog whose security flagship has denied access")
def denied_catalog(context):
    fresh_catalog(context)
    context["catalog"]["models"][1]["access"] = "denied"


@when("I request advice for a documentation edit")
def documentation_advice(context):
    context["advice"] = advise_models("Update the security guide documentation", catalog=context["catalog"])


@when("I request advice for a trust boundary security review")
def security_advice(context):
    context["advice"] = advise_models(
        "Review the authorization trust boundary for bypasses", catalog=context["catalog"]
    )


@when("I request advice without a catalog or current settings")
def missing_catalog(context):
    context["advice"] = advise_models("Implement a report formatter")


@then("the efficient model is suggested at low effort")
def efficient_suggestion(context):
    assert context["advice"]["recommendation"]["model_id"] == "test-efficient"
    assert context["advice"]["recommendation"]["effort"] == "low"


@then("the security flagship is suggested at high effort")
def flagship_suggestion(context):
    assert context["advice"]["recommendation"]["model_id"] == "test-security"
    assert context["advice"]["recommendation"]["effort"] == "high"


@then("no model is suggested and the access exclusion is explained")
def no_suggestion(context):
    assert context["advice"]["recommendation"] is None
    assert "access_denied" in context["advice"]["excluded"]["test-security"]


@then("host discovery is required and current settings are unverified")
def discovery_needed(context):
    assert context["advice"]["status"] == "catalog_required"
    assert context["advice"]["current"]["status"] == "unverified"
