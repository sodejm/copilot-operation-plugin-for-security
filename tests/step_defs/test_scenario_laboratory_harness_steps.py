"""Offline step definitions for signed laboratory observations and remote dispatch."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.execution.worker import WorkerCapabilityInventory
from cops.laboratory import (
    LaboratoryGateError,
    LaboratoryHarness,
    LaboratoryCaseJournal,
    PrerequisiteMismatchError,
    make_inert_action_plan,
    make_inert_container_environment,
)
from tests.auth_testkit import authorize_test_plan, worker_inventory_for_plan
from tests.laboratory_testkit import (
    case_observation,
    endpoint_inventory,
    environment_observation,
    observation_trust_store,
    remote_run,
    reset_receipt,
)

scenarios("../../specs/features/scenario_laboratory_harness.feature")


@pytest.fixture
def lab_ctx(tmp_path):
    inventory = endpoint_inventory(tmp_path)
    harness = LaboratoryHarness(
        observation_provider=lambda environment, nonce: environment_observation(
            environment, nonce, inventory
        ),
        observation_trust_store=observation_trust_store(tmp_path),
        case_journal=LaboratoryCaseJournal(tmp_path / "case-journal.sqlite3"),
    )
    return {"inventory": inventory, "harness": harness}


@given("an inert operator laboratory environment contract")
def given_inert_environment(lab_ctx):
    lab_ctx["environment"] = make_inert_container_environment()


@when("the laboratory harness verifies signed isolation and canary observations")
def when_verify_environment(lab_ctx):
    lab_ctx["harness"].verify_environment(
        lab_ctx["environment"], endpoint_inventory=lab_ctx["inventory"]
    )


@then(parsers.parse('the environment status is "{expected_status}"'))
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
    environment = make_inert_container_environment()
    environment.tool_matrix["kubectl"] = "1.20.0"
    lab_ctx["environment"] = environment


@when("the laboratory harness attempts to verify tool prerequisites")
def when_verify_prerequisites(lab_ctx):
    with pytest.raises(PrerequisiteMismatchError) as error:
        lab_ctx["harness"].verify_environment(
            lab_ctx["environment"], endpoint_inventory=lab_ctx["inventory"]
        )
    lab_ctx["error"] = error.value


@then("verification fails with a prerequisite mismatch error")
def then_prereq_mismatch(lab_ctx):
    assert isinstance(lab_ctx["error"], PrerequisiteMismatchError)


@then("the environment cannot transition to verified")
def then_cannot_transition(lab_ctx):
    assert lab_ctx["environment"].status != "verified"


@given("a verified laboratory environment")
def given_verified_environment(lab_ctx):
    environment = make_inert_container_environment()
    lab_ctx["harness"].verify_environment(
        environment, endpoint_inventory=lab_ctx["inventory"]
    )
    lab_ctx["environment"] = environment


@when("the operator supplies a signed reset receipt for the pending challenge")
def when_reset(lab_ctx):
    environment = lab_ctx["environment"]
    nonce = lab_ctx["harness"].begin_reset(environment)
    receipt = reset_receipt(environment, nonce, lab_ctx["inventory"])
    lab_ctx["harness"].reproducible_reset(
        environment, reset_receipt=receipt, endpoint_inventory=lab_ctx["inventory"]
    )


@then("a reset timestamp is recorded")
def then_reset_timestamp_recorded(lab_ctx):
    assert lab_ctx["environment"].reset_configuration["last_reset_timestamp"]


@then("the canary is verified in the reset environment")
def then_canary_verified_in_reset(lab_ctx):
    assert lab_ctx["environment"].canary["verified"] is True


@given("a verified laboratory environment and signed execution authorization")
def given_verified_env_and_auth(lab_ctx):
    given_verified_environment(lab_ctx)
    environment = lab_ctx["environment"]
    plan = make_inert_action_plan()
    authorization, trust_store, engagement = authorize_test_plan(
        plan, worker_identity=environment.owner
    )
    lab_ctx.update(
        plan=plan,
        authorization=authorization,
        trust_store=trust_store,
        engagement=engagement,
        worker_inventory=worker_inventory_for_plan(
            plan, worker_identity=environment.owner
        ),
        scope_guard=ScopeGuard(
            ScopeDefinition.from_engagement_scope(engagement.scope)
        ),
    )


@when(parsers.parse('the laboratory harness dispatches and classifies a "{case_type}" case'))
def when_dispatch_and_classify(lab_ctx, case_type):
    environment = lab_ctx["environment"]
    plan = lab_ctx["plan"]
    authorization = lab_ctx["authorization"]
    status, exit_code, canary, blocked = {
        "positive": ("success", 0, True, False),
        "remediated": ("success", 0, False, True),
        "negative": ("failed", 1, False, True),
    }[case_type]
    run = remote_run(
        plan, authorization.authorization_id, environment.owner,
        status=status, exit_code=exit_code,
    )
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
        dispatched = lab_ctx["harness"].execute_case(
            environment, plan, authorization, case_type,
            trust_store=lab_ctx["trust_store"],
            engagement=lab_ctx["engagement"],
            worker_inventory=lab_ctx["worker_inventory"],
            endpoint_inventory=lab_ctx["inventory"],
            scope_guard=lab_ctx["scope_guard"],
        )
    observation = case_observation(
        environment, plan, authorization.authorization_id, dispatched,
        lab_ctx["inventory"], request_nonce=lab_ctx["harness"].case_observation_challenge(dispatched),
        canary_token_detected=canary, control_blocked=blocked,
    )
    lab_ctx["case_result"] = lab_ctx["harness"].classify_case(
        environment, plan, dispatched, authorization.authorization_id, case_type,
        case_observation=observation, endpoint_inventory=lab_ctx["inventory"],
    )


@then(parsers.parse('the laboratory case result status is "{expected_status}"'))
def then_case_result_status(lab_ctx, expected_status):
    assert lab_ctx["case_result"].status == expected_status


@then(parsers.parse('the worker cleanup status is "{expected_status}"'))
def then_cleanup_status(lab_ctx, expected_status):
    assert lab_ctx["case_result"].run_result.cleanup_status == expected_status


@then(parsers.parse('positive canary verification is "{expected}"'))
def then_canary_claim(lab_ctx, expected):
    assert lab_ctx["case_result"].canary_verified is (expected == "true")


@given("a directly constructed worker capability inventory")
def given_unverified_inventory(lab_ctx):
    inventory = lab_ctx["worker_inventory"]
    lab_ctx["worker_inventory"] = WorkerCapabilityInventory(**inventory.to_dict())
    assert not lab_ctx["worker_inventory"].is_verified


@when(parsers.parse('the laboratory harness attempts a "{case_type}" case with that inventory'))
def when_unverified_inventory(lab_ctx, case_type):
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute") as dispatch:
        with pytest.raises(LaboratoryGateError) as error:
            lab_ctx["harness"].execute_case(
                lab_ctx["environment"], lab_ctx["plan"], lab_ctx["authorization"],
                case_type, trust_store=lab_ctx["trust_store"],
                engagement=lab_ctx["engagement"],
                worker_inventory=lab_ctx["worker_inventory"],
                endpoint_inventory=lab_ctx["inventory"],
                scope_guard=lab_ctx["scope_guard"],
            )
    lab_ctx["error"] = error.value
    lab_ctx["dispatch"] = dispatch


@then("the inventory gate rejects the laboratory case")
def then_inventory_gate_rejects(lab_ctx):
    assert "verified owner-provisioned worker capability inventory" in str(lab_ctx["error"])


@then("no remote dispatch occurs")
def then_no_remote_dispatch(lab_ctx):
    lab_ctx["dispatch"].assert_not_called()
