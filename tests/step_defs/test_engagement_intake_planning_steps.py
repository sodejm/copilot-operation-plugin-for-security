"""Step definitions for engagement intake and planning BDD scenarios."""

from __future__ import annotations

import copy
from pathlib import Path
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.catalog import ROOT
from cops.contracts.models import ActionPlan, Engagement
from cops.contracts.validation import validate_contract
from cops.engagement import (
    EngagementIntakeError,
    IncompatibleWindowError,
    IncompleteBudgetError,
    IncompleteLiveRequestError,
    MissingOwnerError,
    ScopeAmbiguityError,
    build_action_plan,
    create_engagement_contract,
    validate_engagement_intake,
)

scenarios("../../specs/features/engagement_intake_planning.feature")


@pytest.fixture
def bdd_ctx():
    base_data = {
        "schema_version": "cops.engagement/v1",
        "engagement_id": "eng-bdd-test-01",
        "name": "BDD Intake Assessment",
        "status": "planned",
        "mode": "planning",
        "scope": {
            "included_targets": ["10.0.0.5", "api.internal"],
            "excluded_targets": ["10.0.0.1"],
        },
        "window": {
            "started_at": "2026-10-05T00:00:00Z",
            "authorized_until_utc": "2026-10-05T23:59:59Z",
        },
        "operator": "secops-bdd",
        "rules_of_engagement": {
            "max_intensity": "low",
            "allowed_actions": ["discovery"],
            "emergency_contact": "soc@bdd.corp",
            "safe_mode": True,
        },
        "budget": {
            "max_duration_seconds": 1800,
            "max_output_bytes": 5000000,
        },
        "credential_references": ["test-token"],
        "created_at": "2026-10-05T00:00:00Z",
    }
    return {"data": base_data, "error": None, "validated": None, "plan": None}


@given(parsers.parse('a valid engagement specification with targets "{targets}" and exclusions "{exclusions}"'))
def given_valid_engagement_spec(bdd_ctx, targets, exclusions):
    bdd_ctx["data"]["scope"]["included_targets"] = [t.strip() for t in targets.split(",")]
    bdd_ctx["data"]["scope"]["excluded_targets"] = [e.strip() for e in exclusions.split(",")]


@given("an engagement specification with an empty operator")
def given_empty_operator(bdd_ctx):
    bdd_ctx["data"]["operator"] = ""


@given(parsers.parse('an engagement specification with included target "{target}"'))
def given_target(bdd_ctx, target):
    bdd_ctx["data"]["scope"]["included_targets"] = [target]


@given("an engagement specification with end time preceding start time")
def given_incompatible_window(bdd_ctx):
    bdd_ctx["data"]["window"]["started_at"] = "2026-10-05T12:00:00Z"
    bdd_ctx["data"]["window"]["authorized_until_utc"] = "2026-10-05T10:00:00Z"


@given("an engagement specification with negative budget duration")
def given_negative_budget(bdd_ctx):
    bdd_ctx["data"]["budget"]["max_duration_seconds"] = -100


@given(parsers.parse('an engagement specification requesting mode "{mode}" without an execution budget'))
def given_live_no_budget(bdd_ctx, mode):
    bdd_ctx["data"]["mode"] = mode
    bdd_ctx["data"]["budget"] = None


@given(parsers.parse('a valid bounded engagement and scenario "{scenario_id}"'))
def given_engagement_and_scenario(bdd_ctx, scenario_id):
    bdd_ctx["scenario_id"] = scenario_id


@when("the engagement intake is validated")
def when_intake_validated(bdd_ctx):
    try:
        bdd_ctx["validated"] = validate_engagement_intake(bdd_ctx["data"])
    except EngagementIntakeError as err:
        bdd_ctx["error"] = err


@when(parsers.parse('an action plan is compiled for target "{target}"'))
def when_plan_compiled(bdd_ctx, target):
    eng = Engagement.from_dict(validate_engagement_intake(bdd_ctx["data"]))
    bdd_ctx["plan"] = build_action_plan(
        engagement=eng,
        scenario=bdd_ctx["scenario_id"],
        target=target,
        specialist_id="cops-pentest-specialist",
        root=ROOT,
    )


@then(parsers.parse('the intake validation succeeds with status "{status}"'))
def then_validation_succeeds(bdd_ctx, status):
    assert bdd_ctx["error"] is None
    assert bdd_ctx["validated"] is not None
    assert bdd_ctx["validated"]["status"] == status


@then(parsers.parse("the engagement scope contains {inc:d} included targets and {exc:d} excluded target"))
@then(parsers.parse("the engagement scope contains {inc:d} included targets and {exc:d} excluded targets"))
def then_scope_counts(bdd_ctx, inc, exc):
    assert len(bdd_ctx["validated"]["scope"]["included_targets"]) == inc
    assert len(bdd_ctx["validated"]["scope"].get("excluded_targets", [])) == exc


@then(parsers.parse('the intake validation fails with error "{error_name}"'))
def then_validation_fails(bdd_ctx, error_name):
    assert bdd_ctx["error"] is not None
    assert type(bdd_ctx["error"]).__name__ == error_name


@then(parsers.parse('the action plan status is "{status}"'))
def then_plan_status(bdd_ctx, status):
    assert bdd_ctx["plan"] is not None
    assert bdd_ctx["plan"].status == status


@then("the action plan includes platform prerequisites")
def then_plan_prereqs(bdd_ctx):
    plan = bdd_ctx["plan"]
    assert plan.platform_prerequisites is not None
    assert len(plan.platform_prerequisites) > 0


@then("the action plan operations include expected evidence, side effects, and cleanup obligations")
def then_plan_obligations(bdd_ctx):
    plan = bdd_ctx["plan"]
    assert len(plan.operations) > 0
    op = plan.operations[0]
    assert "expected_evidence" in op
    assert "side_effects" in op
    assert "cleanup" in op


@then("the action plan digest is verifiable")
def then_plan_digest_verifiable(bdd_ctx):
    plan = bdd_ctx["plan"]
    validated = validate_contract(plan.to_dict(), "action_plan")
    assert validated["plan_digest"] == plan.plan_digest
