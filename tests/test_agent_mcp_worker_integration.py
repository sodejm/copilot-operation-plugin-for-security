"""Portable worker wiring evidence; explicit doubles do not qualify Linux isolation."""

from __future__ import annotations

import json
import multiprocessing
import subprocess
import sys
import threading
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

import cops.execution.worker as worker_module
import cops.laboratory.agent_mcp_broker as broker_module
from cops.adapters import ToolAdapterRegistry
from cops.contracts import ActionPlan
from cops.evidence.canonical import digest
from cops.execution import ApprovalStore, IsolatedWorker, WorkerExecutionError, WorkerIsolationError
from cops.execution.authorization import AuthorizationError
from cops.execution.egress import BROKER_FD_ENV
from cops.execution.process import BoundedProcessResult
from cops.laboratory.agent_mcp_worker import AGENT_MCP_TOOL, RESULT_VERSION
from tests.auth_testkit import TestApprovalControl, TestExecutionSandbox, authorize_test_plan, worker_inventory_for_plan
from tests.test_agent_mcp_worker import SECRET, envelope_data


def _plan(document=None):
    fixture = Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json"
    value = json.loads(fixture.read_text())
    value.pop("schema_version")
    value.pop("plan_digest")
    envelope = document or envelope_data()
    envelope = deepcopy(envelope)
    envelope["engagement_id"] = value["engagement_id"]
    envelope["scenario_id"] = value["scenario_id"]
    value["target"] = value["scenario_id"]
    value["credential_references"] = []
    value["operations"] = [
        {
            "step_id": "step-lab",
            "tool": AGENT_MCP_TOOL,
            "tool_version": "1",
            "action": "run",
            "arguments": {"envelope": envelope},
            "idempotent": False,
            "timeout_seconds": 3,
        }
    ]
    return ActionPlan.create(**value)


def _change(plan, change):
    value = plan.to_dict()
    value.pop("schema_version")
    value.pop("plan_digest")
    change(value)
    return ActionPlan.create(**value)


def _worker(tmp_path, monkeypatch, plan, *, dispatcher=None, registry=None, qualify=True):
    (tmp_path / "workspace").mkdir(mode=0o700, parents=True)
    journal = tmp_path / "journal"
    journal.mkdir(mode=0o700)
    store = ApprovalStore(tmp_path / "approval.sqlite3")
    auth, trust, engagement = authorize_test_plan(plan, worker_identity="test-worker-01")
    store.store_authorization(auth)
    control = TestApprovalControl(store, trust, engagement)
    sandbox = TestExecutionSandbox()
    adapters = ToolAdapterRegistry()
    adapter = adapters.get_adapter(AGENT_MCP_TOOL)
    adapter.supported_environments.append("darwin")
    monkeypatch.setattr(worker_module, "verify_executable_launch_support", lambda: None)
    monkeypatch.setattr(
        worker_module,
        "prepare_executable",
        lambda *_a, **_kw: SimpleNamespace(
            invocation_path=sys.executable,
            pass_fds=(),
            remove=lambda: None,
        ),
    )
    if qualify:
        monkeypatch.setattr(worker_module, "LinuxBubblewrapSandbox", TestExecutionSandbox)
    dispatchers = (
        registry
        if registry is not None
        else {
            "agent-mcp-stdio-v1": dispatcher
            or (lambda *_a, **_kw: {"status": "completed", "cleanup": {"verified": True}})
        }
    )
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="test-worker-01"),
        control,
        sandbox,
        cleanup_journal_path=journal / "cleanup.sqlite3",
        adapter_registry=adapters,
        agent_mcp_dispatchers=dispatchers,
    )
    return worker, auth.authorization_id, control, sandbox


def _run_child(command, **kwargs):
    assert kwargs["operation_env"].keys() == {BROKER_FD_ENV}
    assert kwargs["pass_fds"] == () and len(kwargs["capability_fds"]) == 1
    assert SECRET not in repr(command) + repr(kwargs)
    result = subprocess.run(
        command,
        env={**kwargs["env"], **kwargs["operation_env"]},
        pass_fds=kwargs["capability_fds"],
        capture_output=True,
        timeout=kwargs["timeout_seconds"],
        check=False,
    )
    assert json.loads(result.stdout) == {"status": "completed"}
    return BoundedProcessResult(result.stdout, result.stderr, result.returncode, False, False)


def test_worker_dispatches_fixed_capability_and_returns_only_digest_receipt(tmp_path, monkeypatch):
    plan = _plan()
    envelope = plan.to_dict()["operations"][0]["arguments"]["envelope"]

    def dispatcher(approved, *, deadline, cancellation_event, dispatch_context):
        assert approved == envelope and deadline > 0 and not cancellation_event.is_set()
        assert isinstance(dispatch_context, MappingProxyType)
        assert dispatch_context["plan_digest"] == plan.plan_digest
        assert dispatch_context["envelope_digest"] == digest(envelope)
        assert len(dispatch_context["approval_digest"]) == 64
        return {
            "status": "completed",
            "cleanup": {"verified": True},
            "model_output": SECRET,
            "canary": SECRET,
        }

    dispatchers = {"agent-mcp-stdio-v1": dispatcher}
    worker, authorization, control, sandbox = _worker(tmp_path, monkeypatch, plan, registry=dispatchers)
    dispatchers.clear()

    def run(command, **kwargs):
        result = _run_child(command, **kwargs)
        return BoundedProcessResult(SECRET.encode(), SECRET.encode(), result.returncode, False, False)

    sandbox.run_callback = run
    execution = worker.execute_plan_with_receipt(
        plan, authorization_id=authorization, workspace_dir=tmp_path / "workspace"
    )
    assert execution.result.status == "success", execution.result.to_dict()
    assert execution.attempted_operation_ids == ("step-lab",)
    output = dict(execution.operation_outputs["step-lab"])
    assert set(output) == {
        "schema_version",
        "status",
        "envelope_digest",
        "plan_digest",
        "approval_digest",
        "result_digest",
        "result_bytes",
    }
    assert output["schema_version"] == RESULT_VERSION and output["status"] == "completed"
    assert output["plan_digest"] == plan.plan_digest
    assert output["approval_digest"] == execution.approval_receipt.authorization_digest
    assert output["result_digest"] == digest(
        {
            "status": "completed",
            "cleanup": {"verified": True},
            "model_output": SECRET,
            "canary": SECRET,
        }
    )
    assert SECRET not in repr(execution)
    assert control.store.get_authorization(authorization).status == "consumed"
    assert len(control.consume_calls) == 1
    for path in (tmp_path / "workspace").rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes()


@pytest.mark.parametrize(
    "case",
    [
        "dispatcher",
        "mixed",
        "engagement",
        "scenario",
        "target",
        "credentials",
        "egress",
        "command",
        "legacy",
        "direct",
        "scope",
        "sandbox",
    ],
)
def test_invalid_local_capability_fails_before_approval_consumption(tmp_path, monkeypatch, case):
    plan = _plan()

    def mutate(value):
        envelope = value["operations"][0]["arguments"]["envelope"]
        if case == "dispatcher":
            envelope["dispatcher_id"] = "unregistered"
        elif case == "mixed":
            value["operations"].append({**value["operations"][0], "step_id": "step-two"})
            value["batch"]["max_operations"] = 2
        elif case in ("engagement", "scenario"):
            envelope[case + "_id"] = "different-binding"
        elif case == "target":
            value["target"] = "https://example.test/"
        elif case == "credentials":
            value["credential_references"] = ["private-reference"]
        elif case == "egress":
            value["limits"]["egress_allowed"] = True
        elif case == "command":
            envelope["command"] = "forbidden"
        elif case in ("legacy", "direct"):
            value["operations"][0]["tool"] = (
                "foundry-agent-harness/auth-lab" if case == "legacy" else "cops.agent-mcp.direct"
            )

    plan = _change(plan, mutate)
    worker, authorization, control, sandbox = _worker(tmp_path, monkeypatch, plan, qualify=case != "sandbox")
    if case == "scope":
        worker.scope_guard = SimpleNamespace(scope=SimpleNamespace(egress_allowed=False))
    with pytest.raises((WorkerExecutionError, WorkerIsolationError)):
        worker.execute_plan(plan, authorization=authorization, workspace_dir=tmp_path / "workspace")
    assert control.consume_calls == [] and sandbox.run_calls == []
    assert control.store.get_authorization(authorization).status == "approved"


@pytest.mark.parametrize(
    "binding", ["session_id", "role_id", "tenant_id", "case_id", "request_digest", "scenario_digest"]
)
def test_rebound_envelope_cannot_consume_original_approval(tmp_path, monkeypatch, binding):
    plan = _plan()
    worker, authorization, control, sandbox = _worker(tmp_path, monkeypatch, plan)

    def mutate(value):
        value["operations"][0]["arguments"]["envelope"][binding] = "e" * 64 if binding.endswith("digest") else "other"

    changed = _change(plan, mutate)
    with pytest.raises(AuthorizationError):
        worker.execute_plan(changed, authorization=authorization, workspace_dir=tmp_path / "workspace")
    assert sandbox.run_calls == []
    assert control.store.get_authorization(authorization).status == "approved"


@pytest.mark.parametrize(
    "state,cancel,failed_ack",
    [
        (broker_module.DISPATCH_ATTEMPTED_UNCERTAIN, False, False),
        (broker_module.DISPATCH_COMPLETED, True, False),
        (broker_module.DISPATCH_COMPLETED, False, True),
    ],
)
def test_dispatch_without_verified_ack_is_uncertain_and_has_no_output(tmp_path, monkeypatch, state, cancel, failed_ack):
    plan = _plan()
    worker, authorization, _, sandbox = _worker(tmp_path, monkeypatch, plan)
    event = threading.Event()

    class Broker:
        def __init__(self, mediator):
            pass

        @contextmanager
        def open_channel(self, *, deadline, cancellation_event):
            assert cancellation_event is event and deadline > 0
            yield SimpleNamespace(
                environment={BROKER_FD_ENV: "71"}, pass_fds=(71,), result={"secret": SECRET}, dispatch_state=state
            )
            if cancel:
                event.set()

    monkeypatch.setattr(broker_module, "AgentMcpBroker", Broker)
    if failed_ack:
        sandbox.result = BoundedProcessResult(b"", b"", 1, False, False)
    execution = worker.execute_plan_with_receipt(
        plan,
        authorization_id=authorization,
        workspace_dir=tmp_path / "workspace",
        cancellation_event=event,
    )
    assert execution.result.status == "uncertain"
    assert execution.operation_outputs == {} and execution.attempted_operation_ids == ("step-lab",)
    assert SECRET not in repr(execution)


def test_cancellation_before_start_preserves_approval(tmp_path, monkeypatch):
    plan = _plan()
    worker, authorization, control, sandbox = _worker(tmp_path, monkeypatch, plan)
    event = threading.Event()
    event.set()
    with pytest.raises(WorkerExecutionError, match="cancelled"):
        worker.execute_plan_with_receipt(plan, authorization_id=authorization, cancellation_event=event)
    assert control.consume_calls == [] and sandbox.run_calls == []


@pytest.mark.parametrize("failure", ["cancelled", "deadline", "output_budget", "failed_receipt"])
def test_real_broker_failure_reaps_children_and_keeps_attempt_uncertain(tmp_path, monkeypatch, failure):
    document = envelope_data()
    document["limits"] = {"max_duration_seconds": 1, "max_output_bytes": 128}
    plan = _plan(document)
    started = multiprocessing.get_context("fork").Event()
    cancel = threading.Event()
    children_before = {child.pid for child in multiprocessing.active_children()}

    def dispatcher(_approved, *, deadline, cancellation_event, dispatch_context):
        started.set()
        if failure == "output_budget":
            return {
                "status": "completed",
                "cleanup": {"verified": True},
                "model_output": SECRET * 64,
            }
        if failure == "failed_receipt":
            return {"status": "failed", "cleanup": {"verified": True}}
        # The broker must bound even a trusted dispatcher that ignores cancellation.
        threading.Event().wait(10)
        return {"status": "completed", "cleanup": {"verified": True}}

    worker, authorization, control, sandbox = _worker(tmp_path, monkeypatch, plan, dispatcher=dispatcher)
    adapters = []

    def run(command, **kwargs):
        child = subprocess.Popen(
            command,
            env={**kwargs["env"], **kwargs["operation_env"]},
            pass_fds=kwargs["capability_fds"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        adapters.append(child)
        try:
            if failure == "cancelled":
                assert started.wait(2)
                cancel.set()
            stdout, stderr = child.communicate(timeout=4)
            return BoundedProcessResult(stdout, stderr, child.returncode, False, False)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    sandbox.run_callback = run
    execution = worker.execute_plan_with_receipt(
        plan,
        authorization_id=authorization,
        workspace_dir=tmp_path / "workspace",
        cancellation_event=cancel,
    )
    assert execution.result.status == "uncertain", execution.result.to_dict()
    assert execution.operation_outputs == {} and execution.attempted_operation_ids == ("step-lab",)
    assert control.store.get_authorization(authorization).status == "consumed"
    assert adapters and all(child.returncode is not None for child in adapters)
    assert {child.pid for child in multiprocessing.active_children()} == children_before
    assert SECRET not in repr(execution)
