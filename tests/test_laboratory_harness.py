"""Offline contract and gate tests for the scenario laboratory harness."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import canonical
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.execution.ssh_execution import SSHExecutionError
from cops.laboratory import (
    CanaryVerificationError,
    IsolationVerificationError,
    LaboratoryGateError,
    LaboratoryHarness,
    LaboratoryCaseJournal,
    LaboratoryObservation,
    LaboratoryCaseObservation,
    LaboratoryResetReceipt,
    PrerequisiteMismatchError,
    ResetError,
    make_inert_action_plan,
    make_inert_container_environment,
    make_inert_vm_environment,
    parse_version_tuple,
    verify_platform_matrix,
    verify_receipt_signature,
    verify_tool_prerequisites,
    version_ge,
)
from cops.laboratory.cli import command_laboratory
from tests.auth_testkit import authorize_test_plan, worker_inventory_for_plan
from tests.laboratory_testkit import (
    case_observation,
    endpoint_inventory,
    environment_observation,
    observation_trust_store,
    remote_run,
    reset_receipt,
    sign_receipt,
)


def _harness(inventory, provider=None):
    return LaboratoryHarness(observation_provider=provider or (
        lambda environment, nonce: environment_observation(environment, nonce, inventory)
    ), observation_trust_store=observation_trust_store(inventory.resolve("lab-operator").known_hosts_path.parent),
        case_journal=LaboratoryCaseJournal(inventory.resolve("lab-operator").known_hosts_path.parent / "case-journal.sqlite3"))


def _ready_case(tmp_path: Path):
    inventory = endpoint_inventory(tmp_path)
    harness = _harness(inventory)
    environment = make_inert_container_environment()
    harness.verify_environment(environment, endpoint_inventory=inventory)
    plan = make_inert_action_plan()
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity=environment.owner)
    worker_inventory = worker_inventory_for_plan(plan, worker_identity=environment.owner)
    guard = ScopeGuard(ScopeDefinition.from_engagement_scope(engagement.scope))
    return harness, inventory, environment, plan, auth, trust_store, engagement, worker_inventory, guard


def test_matrix_and_registration() -> None:
    harness = LaboratoryHarness()
    assert harness.register_environment(make_inert_container_environment()).status == "registered"
    assert harness.register_environment(make_inert_vm_environment()).environment_type == "vm"
    assert parse_version_tuple("v0.6.0-rc1") == (0, 6, 0)
    assert version_ge("1.24.0", "1.23.9")
    assert not version_ge("1.23.9", "1.24.0")
    with pytest.raises(PrerequisiteMismatchError):
        verify_platform_matrix({"os": "solaris", "distribution": "solaris", "architecture": "x86_64", "runtime": "container"})
    with pytest.raises(PrerequisiteMismatchError):
        verify_tool_prerequisites({"kubectl": "1.28.0"}, required_tools=["kube-bench"])


@pytest.mark.parametrize("factory", [make_inert_container_environment, make_inert_vm_environment])
def test_verification_requires_attested_runtime_measurement(tmp_path: Path, factory) -> None:
    inventory = endpoint_inventory(tmp_path)
    environment = factory()
    harness = _harness(inventory)
    assert harness.verify_environment(environment, endpoint_inventory=inventory).status == "verified"
    assert environment.canary["verified"] is True
    assert environment.isolation["verification_status"] == "verified"
    assert environment.isolation["verification_timestamp"]


@pytest.mark.parametrize("field,value,error", [
    ("network_isolated", False, IsolationVerificationError),
    ("egress_restricted", False, IsolationVerificationError),
    ("canary_digest", "0" * 64, CanaryVerificationError),
    ("baseline_digest", "0" * 64, IsolationVerificationError),
    ("observed_at", (datetime.now(UTC) - timedelta(minutes=3)).isoformat(), IsolationVerificationError),
    ("request_nonce", "wrong-nonce", IsolationVerificationError),
])
def test_false_stale_or_mismatched_measurement_fails_closed(tmp_path: Path, field, value, error) -> None:
    inventory = endpoint_inventory(tmp_path)
    environment = make_inert_container_environment()
    harness = _harness(inventory, lambda env, nonce: environment_observation(env, nonce, inventory, **{field: value}))
    with pytest.raises(error):
        harness.verify_environment(environment, endpoint_inventory=inventory)
    assert environment.status == "failed"
    assert environment.canary["verified"] is False


def test_untrusted_observation_and_missing_provider_fail_closed(tmp_path: Path) -> None:
    inventory = endpoint_inventory(tmp_path)
    environment = make_inert_container_environment()
    with pytest.raises(IsolationVerificationError, match="provider"):
        LaboratoryHarness().verify_environment(environment, endpoint_inventory=inventory)
    environment = make_inert_container_environment()
    harness = _harness(inventory, lambda env, nonce: replace(environment_observation(env, nonce, inventory), signature="0" * 128))
    with pytest.raises(IsolationVerificationError, match="attestation"):
        harness.verify_environment(environment, endpoint_inventory=inventory)
    assert environment.status == "failed"
    environment = make_inert_container_environment()
    harness = LaboratoryHarness(observation_provider=lambda env, nonce: environment_observation(env, nonce, inventory))
    with pytest.raises(IsolationVerificationError, match="attestation"):
        harness.verify_environment(environment, endpoint_inventory=inventory)
    assert environment.status == "failed"
    environment = make_inert_container_environment()
    with pytest.raises(IsolationVerificationError, match="Mock checks"):
        _harness(inventory).verify_environment(environment, endpoint_inventory=inventory, mock_checks=True)


def test_ssh_dispatch_key_cannot_forge_operator_observation(tmp_path: Path) -> None:
    inventory = endpoint_inventory(tmp_path)
    trust_store = observation_trust_store(tmp_path)
    endpoint = inventory.resolve("lab-operator")
    dispatch_key = endpoint.attestation_key

    def forged_provider(environment, nonce):
        observation = environment_observation(environment, nonce, inventory)
        forged_signature = hmac.new(dispatch_key, canonical(observation.unsigned()), hashlib.sha512).hexdigest()
        return replace(observation, signature=forged_signature)

    environment = make_inert_container_environment()
    harness = LaboratoryHarness(observation_provider=forged_provider, observation_trust_store=trust_store)
    with pytest.raises(IsolationVerificationError, match="attestation"):
        harness.verify_environment(environment, endpoint_inventory=inventory)
    assert environment.status == "failed"


@pytest.mark.parametrize("field", ["network_isolated", "egress_restricted"])
def test_configuration_isolation_preconditions(tmp_path: Path, field: str) -> None:
    inventory = endpoint_inventory(tmp_path)
    environment = make_inert_container_environment()
    environment.isolation[field] = False
    with pytest.raises(IsolationVerificationError):
        _harness(inventory).verify_environment(environment, endpoint_inventory=inventory)
    assert environment.status == "failed"


def test_canary_configuration_precondition(tmp_path: Path) -> None:
    inventory = endpoint_inventory(tmp_path)
    environment = make_inert_container_environment()
    environment.canary["location"] = ""
    with pytest.raises(CanaryVerificationError):
        _harness(inventory).verify_environment(environment, endpoint_inventory=inventory)


def test_reset_requires_signed_receipt_and_new_clean_observation(tmp_path: Path) -> None:
    inventory = endpoint_inventory(tmp_path)
    harness = _harness(inventory)
    environment = make_inert_container_environment()
    harness.verify_environment(environment, endpoint_inventory=inventory)
    nonce = harness.begin_reset(environment)
    assert environment.status == "resetting"
    assert environment.canary["verified"] is False
    receipt = reset_receipt(environment, nonce, inventory)
    assert harness.reproducible_reset(environment, reset_receipt=receipt, endpoint_inventory=inventory).status == "verified"
    assert environment.reset_configuration["last_reset_timestamp"]
    with pytest.raises(ResetError, match="no pending"):
        harness.reproducible_reset(environment, reset_receipt=receipt, endpoint_inventory=inventory)


@pytest.mark.parametrize("overrides", [
    {"succeeded": False},
    {"request_nonce": "wrong-nonce"},
    {"completed_at": (datetime.now(UTC) - timedelta(minutes=3)).isoformat()},
])
def test_failed_reset_receipt_invalidates_environment(tmp_path: Path, overrides) -> None:
    inventory = endpoint_inventory(tmp_path)
    harness = _harness(inventory)
    environment = make_inert_container_environment()
    harness.verify_environment(environment, endpoint_inventory=inventory)
    nonce = harness.begin_reset(environment)
    receipt = reset_receipt(environment, nonce, inventory, **overrides)
    with pytest.raises(ResetError):
        harness.reproducible_reset(environment, reset_receipt=receipt, endpoint_inventory=inventory)
    assert environment.status == "failed"
    assert environment.isolation["verification_status"] == "failed"


def test_reset_fails_if_post_reset_baseline_is_dirty(tmp_path: Path) -> None:
    inventory = endpoint_inventory(tmp_path)
    dirty = False

    def provider(environment, nonce):
        baseline = "0" * 64 if dirty else environment.reset_configuration["expected_baseline_digest"]
        return environment_observation(environment, nonce, inventory, baseline_digest=baseline)

    harness = _harness(inventory, provider)
    environment = make_inert_vm_environment()
    harness.verify_environment(environment, endpoint_inventory=inventory)
    nonce = harness.begin_reset(environment)
    receipt = reset_receipt(environment, nonce, inventory)
    dirty = True
    with pytest.raises(ResetError):
        harness.reproducible_reset(environment, reset_receipt=receipt, endpoint_inventory=inventory)
    assert environment.status == "failed"


def test_reset_preconditions_do_not_destroy_verified_state(tmp_path: Path) -> None:
    inventory = endpoint_inventory(tmp_path)
    harness = _harness(inventory)
    environment = make_inert_container_environment()
    harness.verify_environment(environment, endpoint_inventory=inventory)
    environment.reset_configuration["reproducible"] = False
    with pytest.raises(ResetError):
        harness.begin_reset(environment)
    assert environment.status == "verified"
    assert environment.canary["verified"] is True


@pytest.mark.parametrize("case_type,status,exit_code,canary,blocked,expected", [
    ("positive", "success", 0, True, False, "success"),
    ("remediated", "success", 0, False, True, "remediated"),
    ("negative", "failed", 1, False, True, "rejected"),
    ("positive", "success", 0, False, False, "failed"),
    ("remediated", "success", 0, True, True, "failed"),
    ("negative", "failed", 1, True, True, "failed"),
])
def test_case_classification_uses_bound_worker_observation(tmp_path: Path, case_type, status, exit_code, canary, blocked, expected) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    run = remote_run(plan, auth.authorization_id, environment.owner, status=status, exit_code=exit_code)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run) as dispatch:
        dispatched = harness.execute_case(
            environment, plan, auth, case_type,
            trust_store=trust, engagement=engagement, worker_inventory=worker_inventory,
            endpoint_inventory=inventory, scope_guard=guard,
        )
    dispatch.assert_called_once()
    observation = case_observation(
        environment, plan, auth.authorization_id, dispatched, inventory,
        request_nonce=harness.case_observation_challenge(dispatched),
        canary_token_detected=canary, control_blocked=blocked,
    )
    classified = harness.classify_case(
        environment, plan, dispatched, auth.authorization_id, case_type,
        case_observation=observation, endpoint_inventory=inventory,
    )
    assert classified.status == expected
    assert classified.cleanup_receipt is None
    assert classified.details["worker_cleanup_status"] == "completed"
    record, = harness.recorded_cases()
    assert record["state"] == ("failed" if expected == "failed" else "classified")
    assert record["result"] == classified.to_dict()
    with pytest.raises(LaboratoryGateError, match="pending"):
        harness.classify_case(environment, plan, dispatched, auth.authorization_id, case_type, case_observation=observation, endpoint_inventory=inventory)


def test_case_omitted_guard_or_worker_inventory_rejected_before_dispatch(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute") as dispatch:
        with pytest.raises(LaboratoryGateError, match="scope guard"):
            harness.execute_case(environment, plan, auth, trust_store=trust, engagement=engagement, worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=None)
        with pytest.raises(LaboratoryGateError, match="capability inventory"):
            harness.execute_case(environment, plan, auth, trust_store=trust, engagement=engagement, worker_inventory=None, endpoint_inventory=inventory, scope_guard=guard)
        with pytest.raises(LaboratoryGateError, match="SSH endpoint inventory"):
            harness.execute_case(environment, plan, auth, trust_store=trust, engagement=engagement, worker_inventory=worker_inventory, endpoint_inventory=None, scope_guard=guard)
        dispatch.assert_not_called()


def test_fresh_observation_and_egress_gate_precede_dispatch(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    egress_plan = ActionPlan.create(
        plan_id=plan.plan_id,
        engagement_id=plan.engagement_id,
        scenario_id=plan.scenario_id,
        target=plan.target,
        specialist_id=plan.specialist_id,
        operations=[dict(operation) for operation in plan.to_dict()["operations"]],
        limits={**plan.to_dict()["limits"], "egress_allowed": True},
        credential_references=plan.to_dict()["credential_references"],
        created_at=plan.created_at,
        status=plan.status,
        platform_prerequisites=plan.to_dict()["platform_prerequisites"],
        batch=plan.to_dict()["batch"],
    )
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute") as dispatch:
        with pytest.raises(LaboratoryGateError, match="prohibit egress"):
            harness.execute_case(environment, egress_plan, auth, trust_store=trust, engagement=engagement, worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard)
        dispatch.assert_not_called()
    harness.observation_provider = lambda env, nonce: environment_observation(env, nonce, inventory, egress_restricted=False)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute") as dispatch:
        with pytest.raises(LaboratoryGateError, match="fresh runtime verification"):
            harness.execute_case(environment, plan, auth, trust_store=trust, engagement=engagement, worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard)
        dispatch.assert_not_called()
    assert environment.status == "failed"


def test_invalid_case_observation_can_be_replaced_before_classification(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    run = remote_run(plan, auth.authorization_id, environment.owner)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
        harness.execute_case(environment, plan, auth, trust_store=trust, engagement=engagement, worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard)
    valid = case_observation(environment, plan, auth.authorization_id, run, inventory, request_nonce=harness.case_observation_challenge(run), canary_token_detected=True, control_blocked=False)
    with pytest.raises(LaboratoryGateError, match="verification failed"):
        harness.classify_case(environment, plan, run, auth.authorization_id, "positive", case_observation=replace(valid, signature="0" * 128), endpoint_inventory=inventory)
    with pytest.raises(LaboratoryGateError, match="does not match"):
        harness.classify_case(environment, plan, run, auth.authorization_id, "positive", case_observation=sign_receipt(replace(valid, result_id="wrong-result"), inventory), endpoint_inventory=inventory)
    with pytest.raises(LaboratoryGateError, match="does not match"):
        harness.classify_case(environment, plan, run, auth.authorization_id, "positive", case_observation=sign_receipt(replace(valid, request_nonce="wrong-nonce"), inventory), endpoint_inventory=inventory)
    assert harness.classify_case(environment, plan, run, auth.authorization_id, "positive", case_observation=valid, endpoint_inventory=inventory).status == "success"


@pytest.mark.parametrize("transition", ["reset", "reverify"])
def test_environment_transition_invalidates_pending_case(tmp_path: Path, transition: str) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    run = remote_run(plan, auth.authorization_id, environment.owner)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
        harness.execute_case(
            environment, plan, auth, trust_store=trust, engagement=engagement,
            worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard,
        )
    nonce = harness.case_observation_challenge(run)
    if transition == "reset":
        harness.begin_reset(environment)
    else:
        harness.verify_environment(environment, endpoint_inventory=inventory)
    record, = harness.recorded_cases()
    assert record["state"] == "failed"
    assert "invalidated pending case" in record["result"]["details"]["failure_reason"]
    observation = case_observation(
        environment, plan, auth.authorization_id, run, inventory,
        request_nonce=nonce, canary_token_detected=True, control_blocked=False,
    )
    with pytest.raises(LaboratoryGateError, match="pending"):
        harness.classify_case(
            environment, plan, run, auth.authorization_id, "positive",
            case_observation=observation, endpoint_inventory=inventory,
        )


def test_pending_case_is_failed_on_controller_restart(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    run = remote_run(plan, auth.authorization_id, environment.owner)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
        harness.execute_case(
            environment, plan, auth, trust_store=trust, engagement=engagement,
            worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard,
        )
    record, = LaboratoryCaseJournal(harness.case_journal.path).records()
    assert record["state"] == "failed"
    assert record["result"]["run_result"]["result_id"] == run.result.result_id
    assert "controller restart" in record["result"]["details"]["failure_reason"]


def test_missing_observation_expires_to_persisted_failure(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    run = remote_run(plan, auth.authorization_id, environment.owner)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
        harness.execute_case(
            environment, plan, auth, trust_store=trust, engagement=engagement,
            worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard,
        )
    pending = harness._pending_cases[run.result.result_id]
    harness._pending_cases[run.result.result_id] = (
        *pending[:6], (datetime.now(UTC) - timedelta(minutes=3)).isoformat().replace("+00:00", "Z"), pending[7],
    )
    with pytest.raises(LaboratoryGateError, match="pending"):
        harness.case_observation_challenge(run)
    record, = harness.recorded_cases()
    assert record["state"] == "failed"
    assert "before deadline" in record["result"]["details"]["failure_reason"]


@pytest.mark.parametrize("dispatch_error", [SSHExecutionError("disconnected"), RuntimeError("unexpected dispatch failure")])
def test_dispatch_failure_retains_unknown_attempt(tmp_path: Path, dispatch_error: Exception) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", side_effect=dispatch_error) as dispatch:
        with pytest.raises(LaboratoryGateError, match="dispatch failed"):
            harness.execute_case(
                environment, plan, auth, trust_store=trust, engagement=engagement,
                worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard,
            )
    record, = harness.recorded_cases()
    assert record["state"] == "unknown"
    assert record["result"] is None
    assert record["payload"]["failure_reason"] == "trusted worker dispatch outcome unknown"
    request_id = record["payload"]["dispatch_request_id"]
    assert uuid.UUID(request_id).version == 4
    assert dispatch.call_args.kwargs["request_id"] == request_id


def test_case_journal_is_required_before_dispatch(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    harness.case_journal = None
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute") as dispatch:
        with pytest.raises(LaboratoryGateError, match="journal is required"):
            harness.execute_case(
                environment, plan, auth, trust_store=trust, engagement=engagement,
                worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard,
            )
        dispatch.assert_not_called()


def test_saved_case_result_contains_offline_verifiable_operator_evidence(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    reset_nonce = harness.begin_reset(environment)
    harness.reproducible_reset(environment, reset_receipt=reset_receipt(environment, reset_nonce, inventory), endpoint_inventory=inventory)
    run = remote_run(plan, auth.authorization_id, environment.owner)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
        harness.execute_case(environment, plan, auth, trust_store=trust, engagement=engagement, worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard)
    observation = case_observation(
        environment, plan, auth.authorization_id, run, inventory,
        request_nonce=harness.case_observation_challenge(run), canary_token_detected=True, control_blocked=False,
    )
    result = harness.classify_case(environment, plan, run, auth.authorization_id, "positive", case_observation=observation, endpoint_inventory=inventory)
    saved = result.to_dict()["details"]
    receipt_types = {
        "operator_case_observation": LaboratoryCaseObservation,
        "operator_pre_execution_observation": LaboratoryObservation,
        "operator_reset_receipt": LaboratoryResetReceipt,
        "operator_post_reset_observation": LaboratoryObservation,
    }
    for field, receipt_type in receipt_types.items():
        receipt = receipt_type(**saved[field])
        verify_receipt_signature(receipt, trust_store=harness.observation_trust_store, worker_identity=environment.owner)
    altered = replace(LaboratoryCaseObservation(**saved["operator_case_observation"]), canary_token_detected=False)
    with pytest.raises(LaboratoryGateError, match="signature"):
        verify_receipt_signature(altered, trust_store=harness.observation_trust_store, worker_identity=environment.owner)


def test_case_rejects_equal_result_timestamp(tmp_path: Path) -> None:
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    run = remote_run(plan, auth.authorization_id, environment.owner)
    with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
        harness.execute_case(environment, plan, auth, trust_store=trust, engagement=engagement, worker_inventory=worker_inventory, endpoint_inventory=inventory, scope_guard=guard)
    observation = case_observation(environment, plan, auth.authorization_id, run, inventory, request_nonce=harness.case_observation_challenge(run), canary_token_detected=True, control_blocked=False, observed_at=run.result.finished_at)
    with pytest.raises(LaboratoryGateError, match="verification failed"):
        harness.classify_case(environment, plan, run, auth.authorization_id, "positive", case_observation=observation, endpoint_inventory=inventory)


def test_cli_reports_provenance_requirements(capsys) -> None:
    for command in ("verify", "reset", "run"):
        args = argparse.Namespace(lab_command=command, environment="{}", output=None)
        assert command_laboratory(args) == 1
        assert "requires" in capsys.readouterr().err
