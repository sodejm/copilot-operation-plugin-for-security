import os

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.operations.service import OperationService

scenarios("../../specs/features/headless_agent_interface.feature")


@given("a task to inspect a supplied sample", target_fixture="work")
def work():
    return {"task": "Inspect a supplied synthetic sample"}


def invoke(operation, arguments):
    return OperationService().invoke(
        {"schema_version": "cops.operation-request/v1", "operation_id": operation, "arguments": arguments}
    )


@when("the harness creates an exploratory work request", target_fixture="result")
def create(work):
    return invoke("cops.work.request", work)


@then("the request succeeds without an Engagement or ActionPlan")
def lightweight(result):
    assert result["status"] == "succeeded"
    assert result["result"]["execution_authorized"] is False
    assert "engagement" not in result["result"]["request"]


@when("the harness proposes execution outside offline work", target_fixture="result")
def escalate(work):
    return invoke("cops.work.escalate", {"request": work, "action": "Execute in an approved lab"})


@then("the proposal is blocked and grants no authority")
def no_authority(result):
    assert result["status"] == "blocked"
    assert result["result"]["proposal"]["authority"] == "none"
    assert result["result"]["execution_authorized"] is False


@when("the harness supplies a host output path to the tool", target_fixture="result")
def path(work):
    return invoke("cops.work.request", dict(work, output="/private/path-marker"))


@then("the invocation fails without echoing the supplied path")
def no_echo(result):
    assert result["status"] == "failed"
    assert "path-marker" not in str(result)


@given("a private local operation runtime", target_fixture="runtime_service")
def private_runtime(tmp_path):
    if os.name != "posix":
        pytest.skip("private durable state requires POSIX")
    from cops.operations.runs import RunStore

    return OperationService(run_store=RunStore(tmp_path / "private"))


@when("the harness durably accepts a sample task", target_fixture="accepted")
def accept_task(runtime_service):
    return runtime_service.invoke(
        {
            "schema_version": "cops.operation-request/v1",
            "operation_id": "cops.run.create",
            "arguments": {
                "request": {
                    "schema_version": "cops.operation-request/v1",
                    "operation_id": "cops.work.request",
                    "arguments": {"task": "sample"},
                }
            },
        }
    )


@then("the task is queued without execution")
def queued(accepted):
    assert accepted["result"]["state"] == "queued"
    assert accepted["result"]["attempt"] == 0


@when("the harness resumes the accepted sample task", target_fixture="resumed")
def resume(runtime_service, accepted):
    return runtime_service.invoke(
        {
            "schema_version": "cops.operation-request/v1",
            "operation_id": "cops.run.resume",
            "arguments": {"run_id": accepted["result"]["run_id"]},
        }
    )


@then("its result is persisted and another resume does not repeat the attempt")
def persisted(runtime_service, accepted, resumed):
    assert resumed["result"]["state"] == "succeeded"
    assert resumed["result"]["attempt"] == 1
    assert resume(runtime_service, accepted)["result"] == resumed["result"]


@when("the harness asks for durable status without runtime configuration", target_fixture="result")
def unconfigured():
    return invoke("cops.run.status", {"run_id": "run-not-present"})


@then("the runtime blocks without creating state")
def configuration_required(result):
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "runtime_not_configured"


@when("the harness requests a worker operation", target_fixture="result")
def worker_request():
    return invoke("cops.controlled.submit", {})


@then("the operation is unavailable")
def unavailable(result):
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "unknown_operation"


@when("the running pure attempt is cancelled and its lease expires")
def expire_cancelled_pure(runtime_service, accepted):
    store = runtime_service._runtime().store
    store.clock = lambda: 100.0
    run_id = accepted["result"]["run_id"]
    store.claim(run_id)
    store.cancel(run_id)
    store.clock = lambda: 10**12


@then("recovery cancels the pure attempt without another handler call")
def no_pure_retry(runtime_service, accepted, monkeypatch):
    from tests.test_operation_runs import call

    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("cancelled work dispatched")

    monkeypatch.setattr(runtime_service, "_dispatch", forbidden)
    result = call(runtime_service, "cops.run.resume", {"run_id": accepted["result"]["run_id"]})
    assert result["result"]["state"] == "cancelled"
    assert result["result"]["attempt"] == 1
    assert result["result"]["operation_result"] is None
    assert result["result"]["evidence_refs"] == []
    assert calls == []
