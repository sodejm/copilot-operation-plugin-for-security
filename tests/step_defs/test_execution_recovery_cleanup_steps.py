"""Step definitions for execution recovery and cleanup receipts BDD scenarios."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.contracts.models import ActionPlan, CleanupReceipt
from cops.execution import (
    ApprovalStore,
    CleanupManager,
    IsolatedWorker,
    SideEffectLedger,
    WorkerConfig,
    create_execution_authorization,
)

scenarios("../../specs/features/execution_recovery_cleanup.feature")


@pytest.fixture
def recovery_ctx():
    tmp_workspace = Path(tempfile.mkdtemp(prefix="cops-recovery-bdd-"))
    ctx = {"workspace": tmp_workspace}
    yield ctx
    shutil.rmtree(tmp_workspace, ignore_errors=True)
    if "outside_dir" in ctx:
        shutil.rmtree(ctx["outside_dir"], ignore_errors=True)


@given("an initialized side-effect ledger and cleanup manager")
def given_ledger_and_manager(recovery_ctx):
    workspace = recovery_ctx["workspace"]
    ledger = SideEffectLedger("plan-bdd-01", "eng-bdd-01", default_owner="worker-bdd-01")
    manager = CleanupManager(ledger, worker_identity="worker-bdd-01", workspace_dir=workspace)
    recovery_ctx["ledger"] = ledger
    recovery_ctx["manager"] = manager


@given("a temporary file tracked in the side-effect ledger")
def given_temp_file_tracked(recovery_ctx):
    workspace = recovery_ctx["workspace"]
    file_path = workspace / "temp_bdd.txt"
    file_path.write_text("transient state", encoding="utf-8")
    recovery_ctx["file_path"] = file_path
    recovery_ctx["ledger"].record_effect(
        step_id="step-1",
        resource_type="file",
        target=str(file_path),
        cleanup_action="delete",
    )


@given("an external system file tracked in the side-effect ledger")
def given_external_file_tracked(recovery_ctx):
    outside = Path(tempfile.mkdtemp(prefix="cops-external-bdd-"))
    recovery_ctx["outside_dir"] = outside
    ext_file = outside / "system.txt"
    ext_file.write_text("critical external asset", encoding="utf-8")
    recovery_ctx["external_file"] = ext_file
    recovery_ctx["ledger"].record_effect(
        step_id="step-bad",
        resource_type="file",
        target=str(ext_file),
        cleanup_action="delete",
    )


@when("cleanup manager rollback is executed")
def when_execute_rollback(recovery_ctx):
    receipt = recovery_ctx["manager"].rollback()
    recovery_ctx["receipt"] = receipt


@then("the tracked file is removed from disk")
def then_file_removed(recovery_ctx):
    assert not recovery_ctx["file_path"].exists()


@then(parsers.parse('a valid cleanup receipt with status "{status}" is emitted'))
def then_receipt_emitted(recovery_ctx, status):
    receipt = recovery_ctx["receipt"]
    assert isinstance(receipt, CleanupReceipt)
    assert receipt.status == status


@then("the external system file is not removed")
def then_external_file_not_removed(recovery_ctx):
    assert recovery_ctx["external_file"].exists()


@then('the cleanup receipt status is "failed" with unresolved effects')
def then_receipt_failed_unresolved(recovery_ctx):
    receipt = recovery_ctx["receipt"]
    assert receipt.status == "failed"
    assert len(receipt.unresolved_effects) > 0


@given("an isolated worker configured with an approval store")
def given_worker_with_store(recovery_ctx):
    workspace = recovery_ctx["workspace"]
    db_path = workspace / "approvals.sqlite3"
    store = ApprovalStore(db_path)
    worker = IsolatedWorker(WorkerConfig(worker_id="worker-bdd-02"), store=store)
    recovery_ctx["store"] = store
    recovery_ctx["worker"] = worker


@given("an action plan containing a non-idempotent mutating step")
def given_plan_with_non_idempotent_step(recovery_ctx):
    workspace = recovery_ctx["workspace"]
    target_file = workspace / "target_state.txt"
    target_file.write_text("initial state", encoding="utf-8")
    recovery_ctx["target_file"] = target_file

    fixtures_dir = Path(__file__).resolve().parents[2] / "cops" / "contracts" / "fixtures"
    sample_plan = json.loads((fixtures_dir / "valid_action_plan.json").read_text(encoding="utf-8"))
    operations = [
        {
            "step_id": "step-mutate",
            "tool": "inert",
            "action": "mutate",
            "arguments": {},
            "timeout_seconds": 10,
            "idempotent": False,
            "cleanup": {
                "resource_type": "file",
                "target": str(target_file),
                "action": "delete",
            },
        }
    ]
    plan = ActionPlan.create(
        plan_id=sample_plan["plan_id"],
        engagement_id=sample_plan["engagement_id"],
        scenario_id=sample_plan["scenario_id"],
        target=sample_plan["target"],
        specialist_id=sample_plan["specialist_id"],
        operations=operations,
        limits=sample_plan["limits"],
        credential_references=sample_plan["credential_references"],
        created_at=sample_plan["created_at"],
    )
    auth = create_execution_authorization(plan, operator="operator@corp", valid_hours=1)
    recovery_ctx["store"].store_authorization(auth)
    recovery_ctx["plan"] = plan
    recovery_ctx["auth"] = auth


@when("execution is interrupted during the non-idempotent step")
def when_execution_interrupted(recovery_ctx):
    worker = recovery_ctx["worker"]
    plan = recovery_ctx["plan"]
    auth = recovery_ctx["auth"]
    workspace = recovery_ctx["workspace"]

    result = worker.execute_plan(
        plan,
        authorization=auth.authorization_id,
        workspace_dir=workspace,
        failure_injection={"inject_at": "during_execution", "step_id": "step-mutate"},
    )
    recovery_ctx["result"] = result


@then('the run result status is "uncertain"')
def then_status_uncertain(recovery_ctx):
    assert recovery_ctx["result"].status == "uncertain"


@then("automatic retry is disallowed")
def then_retry_disallowed(recovery_ctx):
    reason = recovery_ctx["result"].status_details.get("reason", "")
    assert "automatic repeat disallowed" in reason or "automatic retry disallowed" in reason


@then("cleanup receipt documents verified rollback")
def then_cleanup_documents_rollback(recovery_ctx):
    assert recovery_ctx["result"].cleanup_status == "completed"
    assert not recovery_ctx["target_file"].exists()
