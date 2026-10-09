"""Unit tests for cancellation, recovery, and cleanup receipts (E02.06)."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan, CleanupReceipt
from cops.contracts.validation import validate_contract
from cops.execution import (
    ApprovalStore,
    ApprovalStoreConflictError,
    CleanupManager,
    IsolatedWorker,
    SideEffectLedger,
    WorkerExecutionError,
)
from tests.auth_testkit import (
    TestApprovalControl,
    TestExecutionSandbox,
    authorize_test_plan,
    worker_inventory_for_plan,
)


@pytest.fixture
def temp_workspace():
    path = tempfile.mkdtemp(prefix="cops-cleanup-test-")
    yield Path(path).resolve(strict=True)
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def temp_store(temp_workspace):
    db_path = temp_workspace / "approvals.sqlite3"
    return ApprovalStore(db_path)


@pytest.fixture
def sample_plan():
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    if not (fixtures_dir / "valid_action_plan.json").is_file():
        fixtures_dir = Path(__file__).resolve().parents[1] / "cops" / "contracts" / "fixtures"
    data = json.loads((fixtures_dir / "valid_action_plan.json").read_text(encoding="utf-8"))
    return ActionPlan.from_dict(data)


def test_side_effect_ledger_and_cleanup_manager(temp_workspace):
    """Test side-effect ledger tracking and cleanup rollback execution."""
    plan_id = "plan-test-01"
    engagement_id = "eng-secops-20261002"
    worker_id = "worker-test-01"

    ledger = SideEffectLedger(plan_id, engagement_id, default_owner=worker_id)
    cleanup_manager = CleanupManager(ledger, worker_identity=worker_id, workspace_dir=temp_workspace)

    # Create dummy files
    f1 = temp_workspace / "created_file.txt"
    f1.write_text("temporary resource", encoding="utf-8")
    d1 = temp_workspace / "created_dir"
    d1.mkdir()
    (d1 / "nested.txt").write_text("nested content", encoding="utf-8")

    # Record effects in ledger
    ledger.record_effect(step_id="step-1", resource_type="file", target=str(f1), cleanup_action="delete")
    ledger.record_effect(step_id="step-2", resource_type="directory", target=str(d1), cleanup_action="delete")

    assert len(ledger.get_effects()) == 2
    assert len(ledger.get_effects(status="pending")) == 2

    # Execute rollback
    receipt = cleanup_manager.rollback()

    assert isinstance(receipt, CleanupReceipt)
    assert receipt.status == "completed"
    assert len(receipt.cleaned_effects) == 2
    assert len(receipt.unresolved_effects) == 0
    assert not f1.exists()
    assert not d1.exists()
    validate_contract(receipt.to_dict(), "cleanup_receipt")


def test_cleanup_ownership_and_boundary_enforcement(temp_workspace):
    """Test that cleanup manager refuses to delete resources outside workspace or with wrong owner."""
    outside_dir = tempfile.mkdtemp(prefix="cops-outside-")
    try:
        outside_file = Path(outside_dir) / "critical.txt"
        outside_file.write_text("system asset", encoding="utf-8")

        ledger = SideEffectLedger("plan-test-02", "eng-secops-20261002", default_owner="worker-test-01")
        cleanup_manager = CleanupManager(ledger, worker_identity="worker-test-01", workspace_dir=temp_workspace)

        # 1. Resource outside workspace
        ledger.record_effect(
            step_id="step-bad-path",
            resource_type="file",
            target=str(outside_file),
            cleanup_action="delete",
        )

        receipt = cleanup_manager.rollback()
        assert receipt.status == "failed"
        assert len(receipt.unresolved_effects) == 1
        assert "outside worker workspace" in receipt.unresolved_effects[0]["reason"]
        assert outside_file.exists()  # Did not delete outside file!

        # 2. Resource with wrong owner identity
        inside_file = temp_workspace / "other_owner.txt"
        inside_file.write_text("data", encoding="utf-8")
        ledger2 = SideEffectLedger("plan-test-03", "eng-secops-20261002", default_owner="worker-test-01")
        cleanup_manager2 = CleanupManager(ledger2, worker_identity="worker-test-01", workspace_dir=temp_workspace)
        ledger2.record_effect(
            step_id="step-bad-owner",
            resource_type="file",
            target=str(inside_file),
            owner="worker-other-99",
        )

        receipt2 = cleanup_manager2.rollback()
        assert receipt2.status == "failed"
        assert len(receipt2.unresolved_effects) == 1
        assert "owned by 'worker-other-99'" in receipt2.unresolved_effects[0]["reason"]
        assert inside_file.exists()
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)


def test_failure_injection_after_consume_prevents_replay(temp_store, sample_plan):
    """Test that failure injected after approval consumption marks authorization consumed and prevents replay."""
    plan_data = sample_plan.to_dict()
    plan_data["operations"] = [
        {
            "step_id": "step-inert",
            "tool": "inert",
            "tool_version": "0.7.0",
            "action": "query_status",
            "arguments": {},
            "timeout_seconds": 10,
            "idempotent": True,
        }
    ]
    plan = ActionPlan.create(
        plan_id=sample_plan.plan_id,
        engagement_id=sample_plan.engagement_id,
        scenario_id=sample_plan.scenario_id,
        target=sample_plan.target,
        specialist_id=sample_plan.specialist_id,
        operations=plan_data["operations"],
        limits=plan_data["limits"],
        credential_references=plan_data["credential_references"],
        platform_prerequisites=plan_data["platform_prerequisites"],
        batch=plan_data["batch"],
        created_at=sample_plan.created_at,
    )
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="worker-fail-test")
    temp_store.store_authorization(auth)

    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-fail-test"),
        TestApprovalControl(temp_store, trust_store, engagement),
        TestExecutionSandbox(),
    )

    # Inject failure after consumption
    with pytest.raises(WorkerExecutionError, match="injected failure after approval consumption"):
        worker.execute_plan(
            plan,
            authorization=auth.authorization_id,
            failure_injection={"inject_at": "after_consume"},
        )

    # Verify authorization in store is now consumed
    stored_auth = temp_store.get_authorization(auth.authorization_id)
    assert stored_auth.status == "consumed"

    # Subsequent attempt to execute MUST fail closed (consumed status rejection)
    from cops.execution.authorization import AuthorizationError

    with pytest.raises((ApprovalStoreConflictError, AuthorizationError)):
        worker.execute_plan(plan, authorization=auth.authorization_id)


def test_interruption_uncertain_outcome_non_idempotent(temp_store, sample_plan, temp_workspace):
    """Test that interruption during a non-idempotent operation yields status='uncertain' and does not retry."""
    plan_dict = sample_plan.to_dict()
    plan_dict["operations"] = [
        {
            "step_id": "step-mutating",
            "tool": "inert",
            "tool_version": "0.7.0",
            "action": "modify_state",
            "arguments": {},
            "timeout_seconds": 10,
            "idempotent": False,  # Non-idempotent!
            "cleanup": {
                "resource_type": "file",
                "target": str(temp_workspace / "mutated_state.json"),
                "action": "delete",
            },
        }
    ]
    # Create the file before execution to simulate mutation
    state_file = temp_workspace / "mutated_state.json"
    state_file.write_text('{"state": "mutated"}', encoding="utf-8")

    plan = ActionPlan.create(
        plan_id=sample_plan.plan_id,
        engagement_id=sample_plan.engagement_id,
        scenario_id=sample_plan.scenario_id,
        target=sample_plan.target,
        specialist_id=sample_plan.specialist_id,
        operations=plan_dict["operations"],
        limits=plan_dict["limits"],
        credential_references=plan_dict["credential_references"],
        platform_prerequisites=plan_dict["platform_prerequisites"],
        batch=plan_dict["batch"],
        created_at=sample_plan.created_at,
    )

    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="worker-interrupt-test")
    temp_store.store_authorization(auth)

    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-interrupt-test"),
        TestApprovalControl(temp_store, trust_store, engagement),
        TestExecutionSandbox(),
    )

    # Inject failure during execution of step-mutating
    result = worker.execute_plan(
        plan,
        authorization=auth.authorization_id,
        workspace_dir=temp_workspace,
        failure_injection={"inject_at": "during_execution", "step_id": "step-mutating"},
    )

    # Outcome MUST be uncertain because step was non-idempotent
    assert result.status == "uncertain"
    assert "non-idempotent step" in result.status_details["reason"]
    assert "automatic repeat disallowed" in result.status_details["reason"]
    # Rollback cleaned up the mutated file
    assert result.cleanup_status == "completed"
    assert not state_file.exists()
    assert worker.last_cleanup_receipt is not None
    assert worker.last_cleanup_receipt.status == "completed"


def test_operator_cancellation_idempotent_step(temp_store, sample_plan, temp_workspace):
    """A cancellation requested before dispatch leaves the approval available."""
    plan_dict = sample_plan.to_dict()
    plan_dict["operations"] = [
        {
            "step_id": "step-read-only",
            "tool": "inert",
            "tool_version": "0.7.0",
            "action": "query_status",
            "arguments": {},
            "timeout_seconds": 10,
            "idempotent": True,
        }
    ]
    plan = ActionPlan.create(
        plan_id=sample_plan.plan_id,
        engagement_id=sample_plan.engagement_id,
        scenario_id=sample_plan.scenario_id,
        target=sample_plan.target,
        specialist_id=sample_plan.specialist_id,
        operations=plan_dict["operations"],
        limits=plan_dict["limits"],
        credential_references=plan_dict["credential_references"],
        platform_prerequisites=plan_dict["platform_prerequisites"],
        batch=plan_dict["batch"],
        created_at=sample_plan.created_at,
    )

    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="worker-cancel-test")
    temp_store.store_authorization(auth)

    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-cancel-test"),
        TestApprovalControl(temp_store, trust_store, engagement),
        TestExecutionSandbox(),
    )

    with pytest.raises(WorkerExecutionError, match="cancelled by operator"):
        worker.execute_plan(
            plan,
            authorization=auth.authorization_id,
            workspace_dir=temp_workspace,
            cancel_requested=True,
        )

    assert temp_store.get_authorization(auth.authorization_id).status == "approved"
