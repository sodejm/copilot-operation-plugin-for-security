"""Step definitions for Scenario Laboratory Harness BDD scenarios."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.execution.store import ApprovalStore
from cops.laboratory import (
    LaboratoryHarness,
    PrerequisiteMismatchError,
    make_inert_action_plan,
    make_inert_container_environment,
    make_inert_execution_authorization,
)

scenarios("../../specs/features/scenario_laboratory_harness.feature")


@pytest.fixture
def lab_ctx():
    tmp_dir = tempfile.TemporaryDirectory(prefix="cops-lab-bdd-")
    tmp_path = Path(tmp_dir.name)
    store = ApprovalStore(tmp_path / "approvals.sqlite3")
    harness = LaboratoryHarness(store=store)
    ctx = {
        "tmp_dir": tmp_dir,
        "store": store,
        "harness": harness,
        "environment": None,
        "plan": None,
        "authorization": None,
        "case_result": None,
        "error": None,
    }
    yield ctx
    tmp_dir.cleanup()


@given("an inert operator laboratory environment contract")
def given_inert_environment(lab_ctx):
    lab_ctx["environment"] = make_inert_container_environment()


@when("the laboratory harness verifies the environment isolation and canary data")
def when_verify_environment(lab_ctx):
    lab_ctx["environment"] = lab_ctx["harness"].verify_environment(lab_ctx["environment"])


@then(parsers.parse('the environment status transitions to "{expected_status}"'))
def then_environment_status(lab_ctx, expected_status):
    assert lab_ctx["environment"].status == expected_status


@then(parsers.parse('isolation verification status is "{expected_status}"'))
def then_isolation_status(lab_ctx, expected_status):
    assert lab_ctx["environment"].isolation["verification_status"] == expected_status


@then("the canary token is confirmed")
def then_canary_confirmed(lab_ctx):
    assert lab_ctx["environment"].canary["verified"] is True


@given("an operator laboratory environment with outdated tool versions")
def given_outdated_environment(lab_ctx):
    env = make_inert_container_environment()
    env.tool_matrix["kubectl"] = "1.20.0"  # Requires >= 1.26.0
    lab_ctx["environment"] = env


@when("the laboratory harness attempts to verify tool prerequisites")
def when_verify_prerequisites(lab_ctx):
    try:
        lab_ctx["harness"].verify_environment(lab_ctx["environment"])
    except PrerequisiteMismatchError as err:
        lab_ctx["error"] = err


@then("verification fails with a prerequisite mismatch error")
def then_prereq_mismatch(lab_ctx):
    assert lab_ctx["error"] is not None
    assert isinstance(lab_ctx["error"], PrerequisiteMismatchError)


@then("the environment cannot transition to verified")
def then_cannot_transition(lab_ctx):
    assert lab_ctx["environment"].status != "verified"


@given("a verified laboratory environment")
def given_verified_environment(lab_ctx):
    env = make_inert_container_environment()
    lab_ctx["environment"] = lab_ctx["harness"].verify_environment(env)


@when("the laboratory harness triggers a reproducible reset")
def when_reproducible_reset(lab_ctx):
    lab_ctx["environment"] = lab_ctx["harness"].reproducible_reset(lab_ctx["environment"])


@then("a reset timestamp is recorded")
def then_reset_timestamp_recorded(lab_ctx):
    assert lab_ctx["environment"].reset_configuration.get("last_reset_timestamp") is not None


@then("the canary is verified in the reset environment")
def then_canary_verified_in_reset(lab_ctx):
    assert lab_ctx["environment"].canary["verified"] is True


@given("a verified laboratory environment and signed execution authorization")
def given_verified_env_and_auth(lab_ctx):
    env = make_inert_container_environment()
    lab_ctx["environment"] = lab_ctx["harness"].verify_environment(env)
    plan = make_inert_action_plan()
    auth = make_inert_execution_authorization(plan)
    lab_ctx["plan"] = plan
    lab_ctx["authorization"] = auth


@when("the laboratory harness executes a positive case")
def when_execute_positive(lab_ctx):
    lab_ctx["case_result"] = lab_ctx["harness"].execute_case(
        environment=lab_ctx["environment"],
        action_plan=lab_ctx["plan"],
        authorization=lab_ctx["authorization"],
        case_type="positive",
    )


@then(parsers.parse('the laboratory case result status is "{expected_status}"'))
def then_case_result_status(lab_ctx, expected_status):
    assert lab_ctx["case_result"].status == expected_status


@then("the canary verification succeeds")
def then_canary_succeeds(lab_ctx):
    assert lab_ctx["case_result"].canary_verified is True


@then(parsers.parse('a valid cleanup receipt with status "{expected_status}" is emitted'))
def then_cleanup_receipt_status(lab_ctx, expected_status):
    receipt = lab_ctx["case_result"].cleanup_receipt
    assert receipt is not None
    assert receipt.status == expected_status


@when("the laboratory harness executes a remediated case")
def when_execute_remediated(lab_ctx):
    lab_ctx["case_result"] = lab_ctx["harness"].execute_case(
        environment=lab_ctx["environment"],
        action_plan=lab_ctx["plan"],
        authorization=lab_ctx["authorization"],
        case_type="remediated",
    )


@then("the run result records that the attack was mitigated by active security controls")
def then_run_result_mitigated(lab_ctx):
    run_res = lab_ctx["case_result"].run_result
    assert "mitigated" in run_res.status_details.get("reason", "").lower()


@when("the laboratory harness executes a negative case")
def when_execute_negative(lab_ctx):
    lab_ctx["case_result"] = lab_ctx["harness"].execute_case(
        environment=lab_ctx["environment"],
        action_plan=lab_ctx["plan"],
        authorization=lab_ctx["authorization"],
        case_type="negative",
    )


@then(parsers.parse('the run result status is "{expected_status}"'))
def then_run_result_status(lab_ctx, expected_status):
    assert lab_ctx["case_result"].run_result.status == expected_status


@then("no positive compromise claims are made")
def then_no_positive_claims(lab_ctx):
    assert lab_ctx["case_result"].canary_verified is False
