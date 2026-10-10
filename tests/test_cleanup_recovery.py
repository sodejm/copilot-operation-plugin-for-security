"""Unit tests for cancellation, recovery, and cleanup receipts (E02.06)."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import cops.execution.worker as worker_module
from cops.adapters import (
    ExecutableVerification,
    ToolActionDefinition,
    ToolAdapter,
    ToolAdapterRegistry,
)
from cops.contracts.models import ActionPlan, CleanupReceipt
from cops.contracts.validation import validate_contract
from cops.execution import (
    ApprovalStore,
    ApprovalStoreConflictError,
    AuthorizationError,
    CleanupJournal,
    CleanupManager,
    CleanupPersistenceError,
    EvidenceCaptureError,
    EvidenceRecorder,
    IsolatedWorker,
    SideEffectLedger,
    WorkerExecutionError,
)
from cops.execution.cleanup import (
    PLAN_DECLARED_PROVENANCE_KEY,
    PLAN_DECLARED_PROVENANCE_UNVERIFIED,
)
from cops.execution.process import BoundedProcessResult
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
def temp_journal_path():
    root = Path(tempfile.mkdtemp(prefix="cops-cleanup-journal-")).resolve(strict=True)
    root.chmod(0o700)
    yield root / "cleanup.sqlite3"
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def sample_plan():
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    if not (fixtures_dir / "valid_action_plan.json").is_file():
        fixtures_dir = Path(__file__).resolve().parents[1] / "cops" / "contracts" / "fixtures"
    data = json.loads((fixtures_dir / "valid_action_plan.json").read_text(encoding="utf-8"))
    return ActionPlan.create(
        plan_id=data["plan_id"],
        engagement_id=data["engagement_id"],
        scenario_id=data["scenario_id"],
        target=data["target"],
        specialist_id=data["specialist_id"],
        operations=data["operations"],
        limits=data["limits"],
        credential_references=[],
        created_at=data["created_at"],
        status=data["status"],
        platform_prerequisites=data["platform_prerequisites"],
        batch=data["batch"],
    )


def _adapter_plan(sample_plan: ActionPlan) -> ActionPlan:
    data = sample_plan.to_dict()
    return ActionPlan.create(
        plan_id=sample_plan.plan_id,
        engagement_id=sample_plan.engagement_id,
        scenario_id=sample_plan.scenario_id,
        target=sample_plan.target,
        specialist_id=sample_plan.specialist_id,
        operations=[
            {
                "step_id": "step-fake",
                "tool": "fake-tool",
                "tool_version": "1.0.0",
                "action": "run",
                "arguments": {},
                "timeout_seconds": 10,
                "idempotent": False,
            }
        ],
        limits=data["limits"],
        credential_references=[],
        created_at=sample_plan.created_at,
        platform_prerequisites=data["platform_prerequisites"],
        batch=data["batch"],
    )


def _adapter_registry(temp_workspace: Path) -> ToolAdapterRegistry:
    registry = ToolAdapterRegistry(definitions_path=temp_workspace / "no-definitions")
    registry.register_adapter(
        ToolAdapter(
            tool="fake-tool",
            version="1.0.0",
            binary="fake-tool",
            provenance={
                "source": "https://example.invalid/fake-tool",
                "license": "MIT",
                "pinned_revision": "1.0.0",
            },
            supported_environments=["linux", "darwin"],
            actions={
                "run": ToolActionDefinition(
                    action="run",
                    description="Run a controlled fake-tool result",
                    base_args=[],
                    parameters={},
                )
            },
            executable_verification=ExecutableVerification(
                sha256="0" * 64,
                version_args=("--version",),
                version_pattern=r"(?P<version>[0-9.]+)",
            ),
        )
    )
    return registry


def _authorized_adapter_worker(
    temp_store: ApprovalStore,
    sample_plan: ActionPlan,
    temp_workspace: Path,
    temp_journal_path: Path,
    *,
    worker_identity: str,
):
    plan = _adapter_plan(sample_plan)
    authorization, trust_store, engagement = authorize_test_plan(plan, worker_identity=worker_identity)
    temp_store.store_authorization(authorization)
    registry = _adapter_registry(temp_workspace)
    sandbox = TestExecutionSandbox()
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity=worker_identity),
        TestApprovalControl(temp_store, trust_store, engagement),
        sandbox,
        adapter_registry=registry,
        cleanup_journal_path=temp_journal_path,
    )
    return plan, authorization, trust_store, engagement, registry, sandbox, worker


def _assert_post_dispatch_failure_is_durable(
    *,
    failure_site: str,
    temp_store: ApprovalStore,
    sample_plan: ActionPlan,
    temp_workspace: Path,
    temp_journal_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_identity = f"worker-{failure_site}-test"
    plan, authorization, trust_store, engagement, registry, sandbox, worker = _authorized_adapter_worker(
        temp_store,
        sample_plan,
        temp_workspace,
        temp_journal_path,
        worker_identity=worker_identity,
    )
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "verify_executable_launch_support", lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    launched = 0

    def launch(*args, **kwargs):
        nonlocal launched
        launched += 1
        if failure_site == "launch":
            raise RuntimeError("private launch boundary failure")
        return BoundedProcessResult(b"result", b"", 0, False, False)

    sandbox.run_callback = launch
    if failure_site == "evidence":

        def fail_capture(self, **kwargs):
            raise EvidenceCaptureError("private evidence capture failure")

        monkeypatch.setattr(EvidenceRecorder, "record_step_output", fail_capture)

    workspace = temp_workspace / f"{failure_site}-workspace"
    result = worker.execute_plan(
        plan,
        authorization=authorization.authorization_id,
        workspace_dir=workspace,
    )

    assert launched == 1
    assert result.status == "uncertain"
    assert result.cleanup_status == "not_required"
    assert "automatic repeat disallowed" in result.status_details["reason"]
    assert "private" not in json.dumps(result.to_dict())
    assert temp_store.get_authorization(authorization.authorization_id).status == "consumed"
    assert workspace.is_dir()
    assert worker.last_cleanup_receipt is not None
    assert worker.last_cleanup_receipt.status == "not_required"

    replacement_sandbox = TestExecutionSandbox()
    replacement = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity=worker_identity),
        TestApprovalControl(temp_store, trust_store, engagement),
        replacement_sandbox,
        adapter_registry=registry,
        cleanup_journal_path=temp_journal_path,
    )
    assert replacement.recover_pending_cleanup() == ()
    with pytest.raises((ApprovalStoreConflictError, AuthorizationError, CleanupPersistenceError)):
        replacement.execute_plan(
            plan,
            authorization=authorization.authorization_id,
            workspace_dir=workspace,
        )
    assert replacement_sandbox.run_calls == []


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


def test_failure_injection_after_consume_prevents_replay(temp_store, sample_plan, temp_journal_path):
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
        cleanup_journal_path=temp_journal_path,
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
    replacement = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-fail-test"),
        TestApprovalControl(temp_store, trust_store, engagement),
        TestExecutionSandbox(),
        cleanup_journal_path=temp_journal_path,
    )
    assert replacement.recover_pending_cleanup() == ()
    with pytest.raises((ApprovalStoreConflictError, AuthorizationError, CleanupPersistenceError)):
        replacement.execute_plan(plan, authorization=auth.authorization_id)


@pytest.mark.parametrize("resource_type", ["file", "directory", "process"])
def test_interruption_preserves_unverified_plan_cleanup_target(
    temp_store,
    sample_plan,
    temp_workspace,
    temp_journal_path,
    monkeypatch,
    resource_type,
):
    """Test that interruption during a non-idempotent operation yields status='uncertain' and does not retry."""
    if resource_type == "process":
        cleanup_target = "12345"
    else:
        cleanup_target = str(temp_workspace / "mutated-state")
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
                "resource_type": resource_type,
                "target": cleanup_target,
                "action": "terminate" if resource_type == "process" else "delete",
            },
        }
    ]
    state_path = Path(cleanup_target) if resource_type != "process" else None
    if resource_type == "file":
        assert state_path is not None
        state_path.write_text('{"state": "caller-owned"}', encoding="utf-8")
    elif resource_type == "directory":
        assert state_path is not None
        state_path.mkdir()
        (state_path / "marker.txt").write_text("caller-owned", encoding="utf-8")

    signalled: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, signal: signalled.append((pid, signal)))

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
        cleanup_journal_path=temp_journal_path,
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
    assert result.cleanup_status == "failed"
    assert not signalled
    if resource_type == "file":
        assert state_path is not None
        assert state_path.read_text(encoding="utf-8") == '{"state": "caller-owned"}'
    elif resource_type == "directory":
        assert state_path is not None
        assert (state_path / "marker.txt").read_text(encoding="utf-8") == "caller-owned"
    assert worker.last_cleanup_receipt is not None
    assert worker.last_cleanup_receipt.status == "failed"
    assert "does not establish worker ownership" in (worker.last_cleanup_receipt.unresolved_effects[0]["reason"])

    replacement = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-interrupt-test"),
        TestApprovalControl(temp_store, trust_store, engagement),
        TestExecutionSandbox(),
        cleanup_journal_path=temp_journal_path,
    )
    recovered_receipts = replacement.recover_pending_cleanup()
    assert len(recovered_receipts) == 1
    assert recovered_receipts[0].status == "failed"
    assert not signalled
    if resource_type == "file":
        assert state_path is not None
        assert state_path.read_text(encoding="utf-8") == '{"state": "caller-owned"}'
    elif resource_type == "directory":
        assert state_path is not None
        assert (state_path / "marker.txt").read_text(encoding="utf-8") == "caller-owned"


def test_launch_boundary_failure_is_durable_and_not_replayed(
    temp_store,
    sample_plan,
    temp_workspace,
    temp_journal_path,
    monkeypatch,
):
    """A failure after adapter dispatch keeps an auditable receipt and cannot replay."""
    _assert_post_dispatch_failure_is_durable(
        failure_site="launch",
        temp_store=temp_store,
        sample_plan=sample_plan,
        temp_workspace=temp_workspace,
        temp_journal_path=temp_journal_path,
        monkeypatch=monkeypatch,
    )


def test_evidence_capture_failure_is_durable_and_not_replayed(
    temp_store,
    sample_plan,
    temp_workspace,
    temp_journal_path,
    monkeypatch,
):
    """A post-launch evidence failure keeps an auditable receipt and cannot replay."""
    _assert_post_dispatch_failure_is_durable(
        failure_site="evidence",
        temp_store=temp_store,
        sample_plan=sample_plan,
        temp_workspace=temp_workspace,
        temp_journal_path=temp_journal_path,
        monkeypatch=monkeypatch,
    )


def _durable_ledger(
    journal_path: Path,
    workspace: Path,
    *,
    run_id: str = "run-recovery-test",
) -> tuple[CleanupJournal, SideEffectLedger]:
    journal = CleanupJournal(journal_path)
    ledger = SideEffectLedger(
        "plan-test-01",
        "eng-secops-20261002",
        default_owner="worker-test-01",
        journal=journal,
        run_id=run_id,
        workspace_dir=workspace,
    )
    return journal, ledger


@pytest.mark.parametrize("resource_type", ["file", "directory"])
def test_recovery_preserves_replacement_for_unverified_plan_target(
    temp_workspace,
    temp_journal_path,
    resource_type,
):
    """A target created after journaling is not evidence that the worker owns it."""
    journal, ledger = _durable_ledger(temp_journal_path, temp_workspace)
    target = temp_workspace / "replacement-target"
    ledger.record_effect(
        step_id="step-unverified",
        resource_type=resource_type,
        target=str(target),
        cleanup_action="delete",
        metadata={
            PLAN_DECLARED_PROVENANCE_KEY: PLAN_DECLARED_PROVENANCE_UNVERIFIED,
        },
    )

    if resource_type == "file":
        target.write_text("replacement", encoding="utf-8")
    else:
        target.mkdir()
        (target / "marker.txt").write_text("replacement", encoding="utf-8")

    recovered = journal.recoverable_runs("worker-test-01")[0]
    recovered_ledger = SideEffectLedger(
        recovered.plan_id,
        recovered.engagement_id,
        recovered.worker_identity,
        journal=journal,
        run_id=recovered.run_id,
        workspace_dir=recovered.workspace_dir,
        recovered_effects=recovered.effects,
        start_run=False,
    )
    receipt = CleanupManager(
        recovered_ledger,
        worker_identity=recovered.worker_identity,
        workspace_dir=recovered.workspace_dir,
    ).rollback(recovered=True)

    assert receipt.status == "failed"
    assert recovered_ledger.get_effects()[0].status == "unknown"
    if resource_type == "file":
        assert target.read_text(encoding="utf-8") == "replacement"
    else:
        assert (target / "marker.txt").read_text(encoding="utf-8") == "replacement"


def test_journal_repeated_writes_survive_reopen(temp_workspace, temp_journal_path):
    journal, ledger = _durable_ledger(temp_journal_path, temp_workspace)
    for index in range(64):
        ledger.record_effect(
            step_id=f"step-{index}",
            resource_type="custom",
            target=f"resource-{index}",
        )

    reopened = CleanupJournal(temp_journal_path)
    recovered = reopened.recoverable_runs("worker-test-01")
    assert len(recovered) == 1
    assert len(recovered[0].effects) == 64


def test_recovery_rejects_missing_run_start(temp_workspace, temp_journal_path):
    _durable_ledger(temp_journal_path, temp_workspace)
    with sqlite3.connect(temp_journal_path) as connection:
        connection.execute("DELETE FROM cleanup_events WHERE event_type = 'run_started'")

    with pytest.raises(CleanupPersistenceError, match="missing run_started"):
        CleanupJournal(temp_journal_path).recoverable_runs("worker-test-01")


def test_recovery_rejects_effect_identity_mismatch(temp_workspace, temp_journal_path):
    _, ledger = _durable_ledger(temp_journal_path, temp_workspace)
    effect = ledger.record_effect(
        step_id="step-identity",
        resource_type="custom",
        target="resource-identity",
    )
    payload = effect.to_dict()
    payload["action_plan_id"] = "plan-different"
    with sqlite3.connect(temp_journal_path) as connection:
        connection.execute(
            "UPDATE cleanup_events SET payload_json = ? WHERE event_type = 'effect_recorded'",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
        )

    with pytest.raises(CleanupPersistenceError, match="effect identity"):
        CleanupJournal(temp_journal_path).recoverable_runs("worker-test-01")


def test_recovery_rejects_invalid_workspace(temp_workspace, temp_journal_path):
    _durable_ledger(temp_journal_path, temp_workspace)
    with sqlite3.connect(temp_journal_path) as connection:
        row = connection.execute("SELECT payload_json FROM cleanup_events WHERE event_type = 'run_started'").fetchone()
        payload = json.loads(row[0])
        payload["workspace_dir"] = "relative/workspace"
        connection.execute(
            "UPDATE cleanup_events SET payload_json = ? WHERE event_type = 'run_started'",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
        )

    with pytest.raises(CleanupPersistenceError, match="workspace_dir"):
        CleanupJournal(temp_journal_path).recoverable_runs("worker-test-01")


def test_cleanup_rejects_symlinked_parent(temp_workspace):
    outside_root = Path(tempfile.mkdtemp(prefix="cops-cleanup-outside-"))
    try:
        outside_file = outside_root / "critical.txt"
        outside_file.write_text("preserve", encoding="utf-8")
        (temp_workspace / "linked").symlink_to(outside_root, target_is_directory=True)
        ledger = SideEffectLedger("plan-test-01", "eng-secops-20261002", default_owner="worker-test-01")
        ledger.record_effect(
            step_id="step-symlink",
            resource_type="file",
            target=str(temp_workspace / "linked" / "critical.txt"),
        )

        receipt = CleanupManager(ledger, worker_identity="worker-test-01", workspace_dir=temp_workspace).rollback()

        assert receipt.status == "failed"
        assert "symbolic links" in receipt.unresolved_effects[0]["reason"]
        assert outside_file.read_text(encoding="utf-8") == "preserve"
    finally:
        shutil.rmtree(outside_root, ignore_errors=True)


def test_cleanup_remains_anchored_when_verified_parent_is_replaced(temp_workspace, monkeypatch):
    outside_root = Path(tempfile.mkdtemp(prefix="cops-cleanup-swap-outside-")).resolve(strict=True)
    try:
        owned_parent = temp_workspace / "owned"
        owned_parent.mkdir()
        target = owned_parent / "temporary.txt"
        target.write_text("delete me", encoding="utf-8")
        outside_target = outside_root / target.name
        outside_target.write_text("preserve me", encoding="utf-8")

        ledger = SideEffectLedger("plan-test-01", "eng-secops-20261002", default_owner="worker-test-01")
        ledger.record_effect(
            step_id="step-parent-swap",
            resource_type="file",
            target=str(target),
        )
        manager = CleanupManager(
            ledger,
            worker_identity="worker-test-01",
            workspace_dir=temp_workspace,
        )
        original_transition = manager._transition
        verified_parent = temp_workspace / "verified-parent"

        def replace_parent_after_verification(effect, status, *, details=None):
            original_transition(effect, status, details=details)
            if status == "cleaning":
                owned_parent.rename(verified_parent)
                owned_parent.symlink_to(outside_root, target_is_directory=True)

        monkeypatch.setattr(manager, "_transition", replace_parent_after_verification)
        receipt = manager.rollback()

        assert receipt.status == "completed"
        assert not (verified_parent / target.name).exists()
        assert outside_target.read_text(encoding="utf-8") == "preserve me"
    finally:
        shutil.rmtree(outside_root, ignore_errors=True)


def test_recovered_process_is_never_signalled(temp_workspace, temp_journal_path, monkeypatch):
    _, ledger = _durable_ledger(temp_journal_path, temp_workspace)
    ledger.record_effect(
        step_id="step-process",
        resource_type="process",
        target="12345",
        cleanup_action="terminate",
    )
    recovered = CleanupJournal(temp_journal_path).recoverable_runs("worker-test-01")[0]
    recovered_ledger = SideEffectLedger(
        recovered.plan_id,
        recovered.engagement_id,
        recovered.worker_identity,
        journal=CleanupJournal(temp_journal_path),
        run_id=recovered.run_id,
        workspace_dir=recovered.workspace_dir,
        recovered_effects=recovered.effects,
        start_run=False,
    )
    signalled = False

    def fail_if_signalled(pid, signal):
        nonlocal signalled
        signalled = True
        raise AssertionError((pid, signal))

    monkeypatch.setattr(os, "kill", fail_if_signalled)
    receipt = CleanupManager(
        recovered_ledger,
        worker_identity=recovered.worker_identity,
        workspace_dir=recovered.workspace_dir,
    ).rollback(recovered=True)

    assert not signalled
    assert receipt.status == "failed"
    assert recovered_ledger.get_effects()[0].status == "unknown"


def test_recovery_skips_durably_cleaned_effect(temp_workspace, temp_journal_path):
    journal, ledger = _durable_ledger(temp_journal_path, temp_workspace)
    target = temp_workspace / "already-cleaned.txt"
    target.write_text("first generation", encoding="utf-8")
    effect = ledger.record_effect(step_id="step-cleaned", resource_type="file", target=str(target))
    journal.transition(ledger.run_id, effect, "cleaned", details={"action_taken": "deleted_file"})
    target.unlink()
    target.write_text("replacement", encoding="utf-8")

    recovered = journal.recoverable_runs("worker-test-01")[0]
    recovered_ledger = SideEffectLedger(
        recovered.plan_id,
        recovered.engagement_id,
        recovered.worker_identity,
        journal=journal,
        run_id=recovered.run_id,
        workspace_dir=recovered.workspace_dir,
        recovered_effects=recovered.effects,
        start_run=False,
    )
    receipt = CleanupManager(
        recovered_ledger,
        worker_identity=recovered.worker_identity,
        workspace_dir=recovered.workspace_dir,
    ).rollback(recovered=True)

    assert receipt.status == "not_required"
    assert target.read_text(encoding="utf-8") == "replacement"
    assert journal.recoverable_runs("worker-test-01") == ()


def test_partial_directory_cleanup_failure_is_recorded_as_unknown(temp_workspace, monkeypatch):
    ledger = SideEffectLedger("plan-partial", "eng-partial", "worker-test-01")
    target = temp_workspace / "partially-removed"
    target.mkdir()
    child = target / "child.txt"
    child.write_text("remove before failure", encoding="utf-8")
    effect = ledger.record_effect(
        step_id="step-partial",
        resource_type="directory",
        target=str(target),
        cleanup_action="delete",
    )
    original_rmtree = shutil.rmtree

    def partially_remove_then_fail(path, *args, **kwargs):
        if path == target.name and kwargs.get("dir_fd") is not None:
            directory_fd = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY,
                dir_fd=kwargs["dir_fd"],
            )
            try:
                os.unlink(child.name, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
            raise OSError("injected failure after partial deletion")
        return original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", partially_remove_then_fail)
    receipt = CleanupManager(
        ledger,
        worker_identity="worker-test-01",
        workspace_dir=temp_workspace,
    ).rollback()

    assert receipt.status == "failed"
    assert effect.status == "unknown"
    assert target.is_dir()
    assert not child.exists()
    assert "cleanup outcome unknown after resource action started" in receipt.unresolved_effects[0]["reason"]


def test_receipt_write_failure_is_partial_and_recoverable(temp_workspace, temp_journal_path, monkeypatch):
    journal, ledger = _durable_ledger(temp_journal_path, temp_workspace)
    target = temp_workspace / "receipt-failure.txt"
    target.write_text("cleanup", encoding="utf-8")
    ledger.record_effect(step_id="step-receipt", resource_type="file", target=str(target))
    original_record_receipt = journal.record_receipt

    def fail_record_receipt(run_id, receipt):
        raise CleanupPersistenceError("injected receipt write failure")

    monkeypatch.setattr(journal, "record_receipt", fail_record_receipt)
    receipt = CleanupManager(ledger, worker_identity="worker-test-01", workspace_dir=temp_workspace).rollback()

    assert receipt.status == "partial"
    assert receipt.unresolved_effects[0]["resource_type"] == "cleanup_journal"
    assert not target.exists()
    recovered = journal.recoverable_runs("worker-test-01")
    assert len(recovered) == 1
    assert recovered[0].effects[0].status == "cleaned"

    monkeypatch.setattr(journal, "record_receipt", original_record_receipt)
    recovered_ledger = SideEffectLedger(
        recovered[0].plan_id,
        recovered[0].engagement_id,
        recovered[0].worker_identity,
        journal=journal,
        run_id=recovered[0].run_id,
        workspace_dir=recovered[0].workspace_dir,
        recovered_effects=recovered[0].effects,
        start_run=False,
    )
    recovered_receipt = CleanupManager(
        recovered_ledger,
        worker_identity=recovered[0].worker_identity,
        workspace_dir=recovered[0].workspace_dir,
    ).rollback(recovered=True)
    assert recovered_receipt.status == "not_required"
    assert journal.recoverable_runs("worker-test-01") == ()


def test_inconsistent_completed_receipt_cannot_hide_pending_effect(temp_workspace, temp_journal_path):
    journal, ledger = _durable_ledger(temp_journal_path, temp_workspace)
    target = temp_workspace / "pending-after-corruption.txt"
    target.write_text("cleanup", encoding="utf-8")
    ledger.record_effect(step_id="step-corrupt", resource_type="file", target=str(target))
    receipt = CleanupManager(ledger, worker_identity="worker-test-01", workspace_dir=temp_workspace).rollback()
    assert receipt.status == "completed"

    with sqlite3.connect(temp_journal_path) as connection:
        connection.execute("DELETE FROM cleanup_events WHERE event_type = 'cleanup_transition'")

    recovered = journal.recoverable_runs("worker-test-01")
    assert len(recovered) == 1
    assert recovered[0].effects[0].status == "pending"


def test_journal_path_cannot_be_symlink(temp_journal_path):
    CleanupJournal(temp_journal_path)
    linked_path = temp_journal_path.parent / "linked.sqlite3"
    linked_path.symlink_to(temp_journal_path)

    with pytest.raises(CleanupPersistenceError, match="symbolic link"):
        CleanupJournal(linked_path)


def test_operator_cancellation_idempotent_step(temp_store, sample_plan, temp_workspace, temp_journal_path):
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
        cleanup_journal_path=temp_journal_path,
    )

    with pytest.raises(WorkerExecutionError, match="cancelled by operator"):
        worker.execute_plan(
            plan,
            authorization=auth.authorization_id,
            workspace_dir=temp_workspace,
            cancel_requested=True,
        )

    assert temp_store.get_authorization(auth.authorization_id).status == "approved"
