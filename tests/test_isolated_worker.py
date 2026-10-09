"""Unit tests for COPS isolated execution worker and approval store."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan
from cops.execution import (
    ApprovalStore,
    ApprovalStoreConflictError,
    ApprovalStoreNotFoundError,
    IsolatedWorker,
    LegacyApprovalRecord,
    ScopeDefinition,
    ScopeGuard,
    WorkerExecutionError,
)
from tests.auth_testkit import (
    TestApprovalControl,
    TestExecutionSandbox,
    authorize_test_plan,
    worker_inventory_for_plan,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"


@pytest.fixture
def temp_store(tmp_path):
    db_file = tmp_path / "test_approvals.sqlite3"
    return ApprovalStore(db_file)


@pytest.fixture
def sample_plan() -> ActionPlan:
    data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    return ActionPlan.from_dict(data)


def test_approval_store_roundtrip(temp_store, sample_plan):
    """Test storing, retrieving, and listing authorizations in ApprovalStore."""
    auth, _, _ = authorize_test_plan(sample_plan, worker_identity="worker-01", valid_hours=4)
    temp_store.store_authorization(auth)

    retrieved = temp_store.get_authorization(auth.authorization_id)
    assert retrieved.authorization_id == auth.authorization_id
    assert retrieved.status == "approved"
    assert retrieved.plan_digest == sample_plan.plan_digest

    all_approvals = temp_store.list_approvals()
    assert len(all_approvals) == 1
    assert all_approvals[0].authorization_id == auth.authorization_id


def test_approval_store_not_found(temp_store):
    """Test retrieving non-existent authorization raises ApprovalStoreNotFoundError."""
    with pytest.raises(ApprovalStoreNotFoundError, match="not found in store"):
        temp_store.get_authorization("auth-nonexistent-1234")


def test_legacy_approval_rows_migrate_to_readable_non_executable_records(tmp_path, sample_plan):
    auth, _, _ = authorize_test_plan(sample_plan, worker_identity="legacy-worker")
    db_path = tmp_path / "legacy" / "approvals.sqlite3"
    db_path.parent.mkdir(mode=0o700)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE approvals (
                authorization_id TEXT PRIMARY KEY,
                action_plan_id TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                operator TEXT NOT NULL,
                status TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                authorized_until_utc TEXT NOT NULL,
                bound_parameters_json TEXT NOT NULL,
                approval_mode TEXT NOT NULL,
                signature_digest TEXT NOT NULL,
                consumed_at TEXT,
                consumed_by_worker TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                auth.authorization_id,
                auth.action_plan_id,
                auth.plan_digest,
                auth.engagement_id,
                auth.operator,
                "approved",
                auth.issued_at,
                auth.authorized_until_utc,
                json.dumps(auth.to_dict()["bound_parameters"]),
                auth.approval_mode,
                auth.signature_digest,
                None,
                None,
                "2026-10-02T10:00:00Z",
            ),
        )

    db_path.chmod(0o600)
    store = ApprovalStore(db_path)
    historical = store.get_authorization(auth.authorization_id)
    assert isinstance(historical, LegacyApprovalRecord)
    assert historical.status == "legacy-untrusted"
    assert historical.historical_status == "approved"
    listed = store.list_approvals(status="legacy-untrusted")
    assert len(listed) == 1
    assert isinstance(listed[0], LegacyApprovalRecord)
    assert listed[0].to_dict()["historical_status"] == "approved"
    with pytest.raises(ApprovalStoreConflictError, match="legacy-untrusted"):
        store.atomically_consume(
            auth.authorization_id,
            expected_authorization=auth,
            worker_identity="legacy-worker",
        )


def test_atomic_consume_and_double_spend_prevention(temp_store, sample_plan):
    """Test that atomic consumption succeeds once and subsequent consume fails."""
    auth, _, _ = authorize_test_plan(sample_plan, worker_identity="worker-01", valid_hours=4)
    temp_store.store_authorization(auth)

    # First consume succeeds
    consumed = temp_store.atomically_consume(
        auth.authorization_id,
        expected_authorization=auth,
        worker_identity="worker-01",
    )
    assert consumed.status == "consumed"
    assert consumed.consumed_by_worker == "worker-01"

    # Second consume fails
    with pytest.raises(ApprovalStoreConflictError, match="status is 'consumed'"):
        temp_store.atomically_consume(
            auth.authorization_id,
            expected_authorization=auth,
            worker_identity="worker-02",
        )


def test_concurrent_worker_atomic_consume(temp_store, sample_plan):
    """Test that concurrent worker threads racing to consume the same approval only succeed once."""
    auth, _, _ = authorize_test_plan(sample_plan, worker_identity="worker-01", valid_hours=4)
    temp_store.store_authorization(auth)

    success_workers: list[str] = []
    conflict_count = [0]
    lock = threading.Lock()

    def attempt_consume(worker_name: str):
        try:
            temp_store.atomically_consume(
                auth.authorization_id,
                expected_authorization=auth,
                worker_identity=worker_name,
            )
            with lock:
                success_workers.append(worker_name)
        except ApprovalStoreConflictError:
            with lock:
                conflict_count[0] += 1

    worker_names = ["worker-01", *(f"worker-{i}" for i in range(2, 11))]
    threads = [threading.Thread(target=attempt_consume, args=(name,)) for name in worker_names]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(success_workers) == 1
    assert conflict_count[0] == 9


def test_isolated_worker_execute_plan_success(temp_store, sample_plan):
    """Test worker successfully executing an authorized plan and cleaning up workspace."""
    # Build plan using the worker's explicit inert test tool.
    plan_dict = sample_plan.to_dict()
    plan_dict["operations"] = [
        {
            "step_id": "step-1",
            "tool": "inert",
            "tool_version": "0.7.0",
            "action": "print_status",
            "arguments": {"message": "worker execution successful"},
            "timeout_seconds": 10,
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

    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="test-worker-alpha")
    temp_store.store_authorization(auth)

    approval_control = TestApprovalControl(temp_store, trust_store, engagement)
    sandbox = TestExecutionSandbox()
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="test-worker-alpha"),
        approval_control,
        sandbox,
    )
    result = worker.execute_plan(plan, authorization=auth.authorization_id)

    assert result.is_successful()
    assert result.status == "success"
    assert result.cleanup_status == "completed"
    assert len(result.artifacts) == 1
    assert "step-1" in result.artifacts[0]["name"]

    # Verify authorization is marked consumed in store
    retrieved_auth = temp_store.get_authorization(auth.authorization_id)
    assert retrieved_auth.status == "consumed"


def test_isolated_worker_rejects_unauthorized_tool(temp_store, sample_plan):
    """Test worker rejects plan containing tools not in worker's allowed whitelist."""
    plan_dict = sample_plan.to_dict()
    plan_dict["operations"] = [
        {
            "step_id": "step-unauthorized",
            "tool": "forbidden_tool_x",
            "tool_version": "0.7.0",
            "action": "run",
            "arguments": {},
            "timeout_seconds": 10,
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
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="worker-beta")
    temp_store.store_authorization(auth)

    approval_control = TestApprovalControl(temp_store, trust_store, engagement)
    sandbox = TestExecutionSandbox()
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-beta", allowed_tools=("echo",)),
        approval_control,
        sandbox,
    )
    with pytest.raises(WorkerExecutionError, match="not allowed by this worker"):
        worker.execute_plan(plan, authorization=auth.authorization_id)

    assert temp_store.get_authorization(auth.authorization_id).status == "approved"


@pytest.mark.parametrize("failed_boundary", ["approval-control", "sandbox"])
def test_readiness_failure_stops_execution_before_approval_consumption(
    temp_store, sample_plan, failed_boundary
):
    auth, trust_store, engagement = authorize_test_plan(
        sample_plan, worker_identity="readiness-test"
    )
    temp_store.store_authorization(auth)
    readiness_error = WorkerExecutionError(f"{failed_boundary} unavailable")
    approval_control = TestApprovalControl(
        temp_store,
        trust_store,
        engagement,
        readiness_error=readiness_error if failed_boundary == "approval-control" else None,
    )
    sandbox = TestExecutionSandbox(
        readiness_error=readiness_error if failed_boundary == "sandbox" else None
    )
    worker = IsolatedWorker(
        worker_inventory_for_plan(sample_plan, worker_identity="readiness-test"),
        approval_control,
        sandbox,
    )

    with pytest.raises(WorkerExecutionError, match=f"{failed_boundary} unavailable"):
        worker.execute_plan(sample_plan, authorization=auth.authorization_id)

    assert approval_control.consume_calls == []
    assert sandbox.run_calls == []
    assert temp_store.get_authorization(auth.authorization_id).status == "approved"


@pytest.mark.parametrize("rejection", ["cancel", "plan_target", "operation_destination"])
def test_request_preflight_rejects_without_consuming_approval_or_preparing_workspace(
    temp_store, sample_plan, tmp_path, rejection
):
    plan = sample_plan
    if rejection == "operation_destination":
        data = sample_plan.to_dict()
        operations = [dict(operation) for operation in data["operations"]]
        operations[0]["arguments"] = {**operations[0]["arguments"], "host": "8.8.8.8"}
        plan = ActionPlan.create(
            plan_id=sample_plan.plan_id,
            engagement_id=sample_plan.engagement_id,
            scenario_id=sample_plan.scenario_id,
            target=sample_plan.target,
            specialist_id=sample_plan.specialist_id,
            operations=operations,
            limits=data["limits"],
            credential_references=data["credential_references"],
            platform_prerequisites=data["platform_prerequisites"],
            batch=data["batch"],
            created_at=sample_plan.created_at,
        )

    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="preflight-worker")
    temp_store.store_authorization(auth)
    approval_control = TestApprovalControl(temp_store, trust_store, engagement)
    sandbox = TestExecutionSandbox()
    allowed_ip = "10.0.0.6" if rejection == "plan_target" else "10.0.0.5"
    guard = ScopeGuard(
        ScopeDefinition(included_ips={ipaddress.ip_address(allowed_ip)}),
        resolver=lambda _: [],
    )
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="preflight-worker"),
        approval_control,
        sandbox,
        scope_guard=guard,
    )
    workspace = tmp_path / "unprepared-workspace"

    expected = "cancelled by operator" if rejection == "cancel" else "scope violation"
    with pytest.raises(WorkerExecutionError, match=expected):
        worker.execute_plan(
            plan,
            authorization=auth.authorization_id,
            workspace_dir=workspace,
            cancel_requested=rejection == "cancel",
        )

    assert not workspace.exists()
    assert approval_control.ready_workers == []
    assert approval_control.consume_calls == []
    assert sandbox.ready_calls == []
    assert sandbox.run_calls == []
    assert temp_store.get_authorization(auth.authorization_id).status == "approved"
