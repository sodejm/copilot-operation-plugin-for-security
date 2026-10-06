"""Step definitions for isolated worker and approval store BDD feature."""

from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.contracts.models import ActionPlan
from cops.execution import (
    ApprovalStore,
    ApprovalStoreConflictError,
    IsolatedWorker,
    WorkerConfig,
    create_execution_authorization,
)

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
            "tool": "echo",
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
    auth = create_execution_authorization(
        plan,
        operator="secops@corp.internal",
        valid_hours=2,
    )
    worker_context["plan"] = plan
    worker_context["auth"] = auth


@when("the authorization envelope is registered in the approval store")
def register_auth(worker_context):
    worker_context["store"].store_authorization(worker_context["auth"])


@when("the isolated worker executes the authorized plan")
def execute_plan(worker_context):
    worker = IsolatedWorker(WorkerConfig(worker_id="test-worker-01"), store=worker_context["store"])
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
    auth_id = worker_context["auth"].authorization_id
    successes = []
    conflicts = []
    lock = threading.Lock()

    def worker_task(w_id):
        try:
            store.atomically_consume(auth_id, worker_identity=w_id)
            with lock:
                successes.append(w_id)
        except ApprovalStoreConflictError:
            with lock:
                conflicts.append(w_id)

    threads = [threading.Thread(target=worker_task, args=(f"worker-node-{i}",)) for i in range(8)]
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
    worker_context["worker"] = IsolatedWorker(
        WorkerConfig(worker_id="worker-strict", allowed_tools=(allowed_tool,)),
        store=worker_context["store"],
    )


@given(parsers.parse('an authorized action plan requesting an unapproved tool "{unapproved_tool}"'))
def plan_unapproved_tool(worker_context, unapproved_tool):
    plan_data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan_dict = plan_data.copy()
    plan_dict["operations"] = [
        {
            "step_id": "step-bad",
            "tool": unapproved_tool,
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
    auth = create_execution_authorization(plan, operator="op", valid_hours=1)
    worker_context["store"].store_authorization(auth)
    worker_context["bad_plan"] = plan
    worker_context["bad_auth"] = auth


@when("the worker executes the plan")
def execute_bad_plan(worker_context):
    res = worker_context["worker"].execute_plan(
        worker_context["bad_plan"],
        authorization=worker_context["bad_auth"].authorization_id,
    )
    worker_context["bad_result"] = res


@then(parsers.parse('execution fails with status "{expected_status}"'))
def verify_bad_status(worker_context, expected_status):
    assert worker_context["bad_result"].status == expected_status


@then("the status details state that the tool is not allowed")
def verify_bad_details(worker_context):
    assert "not in worker allowed tools" in worker_context["bad_result"].status_details["reason"]
