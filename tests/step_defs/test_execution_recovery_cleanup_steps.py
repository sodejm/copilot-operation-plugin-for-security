"""Step definitions for execution recovery and cleanup receipts BDD scenarios."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.contracts.models import ActionPlan, CleanupReceipt
from cops.execution import (
    ApprovalStore,
    CleanupJournal,
    CleanupManager,
    CleanupPersistenceError,
    IsolatedWorker,
    SideEffectLedger,
)
from tests.auth_testkit import (
    TestApprovalControl,
    TestExecutionSandbox,
    authorize_test_plan,
    worker_inventory_for_plan,
)

scenarios("../../specs/features/execution_recovery_cleanup.feature")


@pytest.fixture
def recovery_ctx():
    tmp_workspace = Path(tempfile.mkdtemp(prefix="cops-recovery-bdd-")).resolve(strict=True)
    journal_root = Path(tempfile.mkdtemp(prefix="cops-recovery-journal-")).resolve(strict=True)
    ctx = {
        "workspace": tmp_workspace,
        "journal_path": journal_root / "cleanup.sqlite3",
    }
    yield ctx
    shutil.rmtree(tmp_workspace, ignore_errors=True)
    shutil.rmtree(journal_root, ignore_errors=True)
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
    recovery_ctx["store"] = store


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
            "tool_version": "0.7.0",
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
        credential_references=[],
        created_at=sample_plan["created_at"],
    )
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="worker-bdd-02")
    recovery_ctx["store"].store_authorization(auth)
    recovery_ctx["plan"] = plan
    recovery_ctx["auth"] = auth
    recovery_ctx["worker"] = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-bdd-02"),
        TestApprovalControl(recovery_ctx["store"], trust_store, engagement),
        TestExecutionSandbox(),
        cleanup_journal_path=recovery_ctx["journal_path"],
    )


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


@then("cleanup receipt documents unresolved caller-owned state")
def then_cleanup_documents_unresolved_caller_state(recovery_ctx):
    assert recovery_ctx["result"].cleanup_status == "failed"
    assert recovery_ctx["target_file"].exists()
    receipt = recovery_ctx["worker"].last_cleanup_receipt
    assert receipt is not None
    assert receipt.status == "failed"
    assert len(receipt.unresolved_effects) == 1
    assert "does not establish worker ownership" in receipt.unresolved_effects[0]["reason"]


@given("a durable cleanup journal containing unresolved worker-owned side effects")
def given_durable_cleanup_journal(recovery_ctx):
    workspace = recovery_ctx["workspace"]
    journal_root = workspace / "cleanup-journal"
    journal_root.mkdir(mode=0o700)
    journal = CleanupJournal(journal_root / "cleanup.sqlite3")
    run_workspace = workspace / "run-workspace"
    run_workspace.mkdir()
    ledger = SideEffectLedger(
        "plan-bdd-restart",
        "eng-bdd-restart",
        "worker-bdd-restart",
        journal=journal,
        run_id="run-bdd-restart",
        workspace_dir=run_workspace,
    )

    cleaned_path = run_workspace / "already-cleaned.txt"
    cleaned_path.write_text("first generation", encoding="utf-8")
    cleaned_effect = ledger.record_effect(
        step_id="step-cleaned",
        resource_type="file",
        target=str(cleaned_path),
        cleanup_action="delete",
    )
    ledger.transition_effect(cleaned_effect, "cleaning")
    cleaned_path.unlink()
    ledger.transition_effect(cleaned_effect, "cleaned", details={"action_taken": "deleted_file"})
    cleaned_path.write_text("replacement generation", encoding="utf-8")

    interrupted_path = run_workspace / "interrupted"
    interrupted_path.mkdir()
    interrupted_effect = ledger.record_effect(
        step_id="step-interrupted",
        resource_type="directory",
        target=str(interrupted_path),
        cleanup_action="delete",
    )
    ledger.record_effect(
        step_id="step-process",
        resource_type="process",
        target=str(os.getpid()),
        cleanup_action="terminate",
    )
    recovery_ctx.update(
        journal=journal,
        cleaned_path=cleaned_path,
        interrupted_effect_id=interrupted_effect.effect_id,
    )


@given("one cleanup transition was interrupted before its terminal journal record")
def given_interrupted_cleanup_transition(recovery_ctx):
    recovered = recovery_ctx["journal"].recoverable_runs("worker-bdd-restart")[0]
    interrupted_effect = next(
        effect for effect in recovered.effects if effect.effect_id == recovery_ctx["interrupted_effect_id"]
    )
    recovery_ctx["journal"].transition(recovered.run_id, interrupted_effect, "cleaning")


@when("a replacement worker recovers the cleanup journal")
def when_replacement_worker_recovers(recovery_ctx, monkeypatch):
    journal = recovery_ctx["journal"]
    recovered = journal.recoverable_runs("worker-bdd-restart")[0]
    ledger = SideEffectLedger(
        recovered.plan_id,
        recovered.engagement_id,
        recovered.worker_identity,
        journal=journal,
        run_id=recovered.run_id,
        workspace_dir=recovered.workspace_dir,
        recovered_effects=recovered.effects,
        start_run=False,
    )
    signalled: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, signal: signalled.append((pid, signal)))

    def fail_receipt_write(_run_id, _receipt):
        raise CleanupPersistenceError("injected receipt persistence failure")

    monkeypatch.setattr(journal, "record_receipt", fail_receipt_write)
    recovery_ctx["receipt"] = CleanupManager(
        ledger,
        worker_identity=recovered.worker_identity,
        workspace_dir=recovered.workspace_dir,
    ).rollback(recovered=True)
    recovery_ctx["recovered_ledger"] = ledger
    recovery_ctx["signalled"] = signalled


@then("already-cleaned effects are not replayed")
def then_cleaned_effect_not_replayed(recovery_ctx):
    assert recovery_ctx["cleaned_path"].read_text(encoding="utf-8") == "replacement generation"


@then("the interrupted cleanup outcome is recorded as unknown")
def then_interrupted_outcome_unknown(recovery_ctx):
    interrupted_effect = next(
        effect
        for effect in recovery_ctx["recovered_ledger"].get_effects()
        if effect.effect_id == recovery_ctx["interrupted_effect_id"]
    )
    assert interrupted_effect.status == "unknown"


@then("recovered process identifiers are not signalled")
def then_recovered_process_not_signalled(recovery_ctx):
    assert recovery_ctx["signalled"] == []


@then("persistence failures produce an explicit partial or failed cleanup receipt")
def then_persistence_failure_is_explicit(recovery_ctx):
    receipt = recovery_ctx["receipt"]
    assert receipt.status in {"partial", "failed"}
    assert any(
        unresolved["resource_type"] == "cleanup_journal" and "receipt persistence failed" in unresolved["reason"]
        for unresolved in receipt.unresolved_effects
    )
