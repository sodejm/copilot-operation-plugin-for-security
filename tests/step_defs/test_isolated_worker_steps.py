"""Step definitions for isolated worker and approval store BDD feature."""

from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

import cops.execution.worker as worker_module
from cops.adapters import (
    ExecutableVerification,
    ToolActionDefinition,
    ToolAdapter,
    ToolAdapterRegistry,
)
from cops.contracts.models import ActionPlan
from cops.execution import (
    ApprovalStore,
    ApprovalStoreConflictError,
    IsolatedWorker,
    WorkerExecutionError,
)
from cops.execution.process import BoundedProcessResult
from tests.auth_testkit import authorize_test_plan, worker_inventory_for_plan

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"

scenarios("../../specs/features/isolated_worker_approval_store.feature")


@pytest.fixture
def worker_context():
    temp_dir = tempfile.mkdtemp()
    db_file = Path(temp_dir) / "store.sqlite3"
    ctx = {
        "temp_dir": temp_dir,
        "db_file": db_file,
        "store": ApprovalStore(db_file),
    }
    yield ctx
    import shutil

    shutil.rmtree(temp_dir, ignore_errors=True)


@given("an initialized SQLite approval store")
def init_store(worker_context):
    assert worker_context["store"] is not None


@given("a valid action plan and signed authorization envelope")
def load_plan_and_auth(worker_context):
    plan_data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan_dict = plan_data.copy()
    plan_dict["operations"] = [
        {
            "step_id": "step-echo",
            "tool": "inert",
            "tool_version": "0.7.0",
            "action": "run_echo",
            "arguments": {"message": "hello world"},
            "timeout_seconds": 15,
        }
    ]
    plan = ActionPlan.create(
        plan_id=plan_dict["plan_id"],
        engagement_id=plan_dict["engagement_id"],
        scenario_id=plan_dict["scenario_id"],
        target=plan_dict["target"],
        specialist_id=plan_dict["specialist_id"],
        operations=plan_dict["operations"],
        limits=plan_dict["limits"],
        credential_references=plan_dict["credential_references"],
        created_at=plan_dict["created_at"],
    )
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="test-worker-01", valid_hours=2)
    worker_context["plan"] = plan
    worker_context["auth"] = auth
    worker_context["trust_store"] = trust_store
    worker_context["engagement"] = engagement


@when("the authorization envelope is registered in the approval store")
def register_auth(worker_context):
    worker_context["store"].store_authorization(worker_context["auth"])


@when("the isolated worker executes the authorized plan")
def execute_plan(worker_context):
    worker = IsolatedWorker(
        worker_inventory_for_plan(worker_context["plan"], worker_identity="test-worker-01"),
        store=worker_context["store"],
        trust_store=worker_context["trust_store"],
        engagement=worker_context["engagement"],
    )
    result = worker.execute_plan(
        worker_context["plan"],
        authorization=worker_context["auth"].authorization_id,
    )
    worker_context["result"] = result


@then(parsers.parse('the execution result is "{expected_status}"'))
def verify_result_status(worker_context, expected_status):
    assert worker_context["result"].status == expected_status


@then(parsers.parse('the authorization status in the approval store is updated to "{expected_status}"'))
def verify_store_status(worker_context, expected_status):
    retrieved = worker_context["store"].get_authorization(worker_context["auth"].authorization_id)
    assert retrieved.status == expected_status


@then("the ephemeral workspace directory is cleaned up")
def verify_cleanup(worker_context):
    assert worker_context["result"].cleanup_status == "completed"


@given("an approved authorization envelope in the approval store")
def approved_in_store(worker_context):
    load_plan_and_auth(worker_context)
    worker_context["store"].store_authorization(worker_context["auth"])


@when("multiple worker threads attempt to atomically consume the approval simultaneously")
def race_consume(worker_context):
    store = worker_context["store"]
    auth = worker_context["auth"]
    auth_id = auth.authorization_id
    successes = []
    conflicts = []
    lock = threading.Lock()

    def worker_task(w_id):
        try:
            store.atomically_consume(
                auth_id,
                expected_authorization=auth,
                worker_identity=w_id,
            )
            with lock:
                successes.append(w_id)
        except ApprovalStoreConflictError:
            with lock:
                conflicts.append(w_id)

    worker_ids = ["test-worker-01", *(f"worker-node-{i}" for i in range(7))]
    threads = [threading.Thread(target=worker_task, args=(worker_id,)) for worker_id in worker_ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    worker_context["race_successes"] = successes
    worker_context["race_conflicts"] = conflicts


@then("exactly one worker successfully consumes the approval")
def verify_one_success(worker_context):
    assert len(worker_context["race_successes"]) == 1


@then("all other worker requests fail with a conflict error")
def verify_conflicts(worker_context):
    assert len(worker_context["race_conflicts"]) == 7


@given(parsers.parse('an isolated worker configured with allowed tools "{allowed_tool}"'))
def worker_with_tool(worker_context, allowed_tool):
    worker_context["allowed_tool"] = allowed_tool


@given(parsers.parse('an authorized action plan requesting an unapproved tool "{unapproved_tool}"'))
def plan_unapproved_tool(worker_context, unapproved_tool):
    plan_data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan_dict = plan_data.copy()
    plan_dict["operations"] = [
        {
            "step_id": "step-bad",
            "tool": unapproved_tool,
            "tool_version": "0.7.0",
            "action": "run_bad",
            "arguments": {},
            "timeout_seconds": 10,
        }
    ]
    plan = ActionPlan.create(
        plan_id=plan_dict["plan_id"],
        engagement_id=plan_dict["engagement_id"],
        scenario_id=plan_dict["scenario_id"],
        target=plan_dict["target"],
        specialist_id=plan_dict["specialist_id"],
        operations=plan_dict["operations"],
        limits=plan_dict["limits"],
        credential_references=plan_dict["credential_references"],
        created_at=plan_dict["created_at"],
    )
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="worker-strict")
    worker_context["store"].store_authorization(auth)
    worker_context["bad_plan"] = plan
    worker_context["bad_auth"] = auth
    worker_context["worker"] = IsolatedWorker(
        worker_inventory_for_plan(
            plan,
            worker_identity="worker-strict",
            allowed_tools=(worker_context["allowed_tool"],),
        ),
        store=worker_context["store"],
        trust_store=trust_store,
        engagement=engagement,
    )


@when("the worker executes the plan")
def execute_bad_plan(worker_context):
    try:
        worker_context["worker"].execute_plan(
            worker_context["bad_plan"],
            authorization=worker_context["bad_auth"].authorization_id,
        )
    except WorkerExecutionError as exc:
        worker_context["bad_error"] = exc


@then(parsers.parse('execution fails with status "{expected_status}"'))
def verify_bad_status(worker_context, expected_status):
    assert expected_status == "failed"
    assert isinstance(worker_context.get("bad_error"), WorkerExecutionError)
    stored = worker_context["store"].get_authorization(worker_context["bad_auth"].authorization_id)
    assert stored.status == "approved"


@then("the status details state that the tool is not allowed")
def verify_bad_details(worker_context):
    assert "not allowed by this worker" in str(worker_context["bad_error"])


@given("an authorized fake adapter action plan")
def authorized_fake_adapter_plan(worker_context):
    fixture = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    limits = dict(fixture["limits"])
    limits["max_output_bytes"] = 4096
    plan = ActionPlan.create(
        plan_id="plan-fake-adapter-outcomes",
        engagement_id=fixture["engagement_id"],
        scenario_id=fixture["scenario_id"],
        target=fixture["target"],
        specialist_id=fixture["specialist_id"],
        operations=[
            {
                "step_id": "step-fake",
                "tool": "fake-tool",
                "tool_version": "1.0.0",
                "action": "run",
                "arguments": {},
                "timeout_seconds": 5,
            }
        ],
        limits=limits,
        credential_references=[],
        created_at=fixture["created_at"],
    )
    authorization, trust_store, engagement = authorize_test_plan(plan, worker_identity="test-worker-01", valid_hours=2)
    worker_context["store"].store_authorization(authorization)
    registry = ToolAdapterRegistry(definitions_path=Path(worker_context["temp_dir"]) / "no-definitions")
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
                    description="Return a controlled fake result",
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
    worker_context["fake_plan"] = plan
    worker_context["fake_authorization"] = authorization.authorization_id
    worker_context["fake_worker"] = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="test-worker-01"),
        store=worker_context["store"],
        trust_store=trust_store,
        engagement=engagement,
        adapter_registry=registry,
    )


@when(parsers.parse('the fake adapter reports "{outcome}"'))
def fake_adapter_reports(worker_context, monkeypatch, outcome):
    outcomes = {
        "success": BoundedProcessResult(b"ok\n", b"", 0, False, False),
        "timeout": BoundedProcessResult(b"", b"", -9, True, False),
        "output overflow": BoundedProcessResult(b"x" * 64, b"", -9, False, True),
        "failure": BoundedProcessResult(b"", b"failed\n", 9, False, False),
    }
    prepared = SimpleNamespace(
        invocation_path="/proc/self/fd/7",
        pass_fds=(),
        remove=lambda: None,
    )
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    monkeypatch.setattr(
        worker_module,
        "run_bounded_process",
        lambda *args, **kwargs: outcomes[outcome],
    )
    worker_context["result"] = worker_context["fake_worker"].execute_plan(
        worker_context["fake_plan"],
        authorization=worker_context["fake_authorization"],
        workspace_dir=Path(worker_context["temp_dir"]).resolve() / "fake-workspace",
    )


@then(parsers.parse("the execution exit code is {expected_exit_code:d}"))
def verify_result_exit_code(worker_context, expected_exit_code):
    assert worker_context["result"].exit_code == expected_exit_code


@then("the persisted adapter output is empty")
def verify_persisted_output_empty(worker_context):
    result = worker_context["result"]
    artifact_path = Path(worker_context["temp_dir"]).resolve() / "fake-workspace" / result.artifacts[0]["path"]
    assert artifact_path.read_bytes() == b""
