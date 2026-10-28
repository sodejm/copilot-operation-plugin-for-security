"""Portable worker wiring contracts; the sandbox/authority are explicit doubles."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

import cops.execution.worker as worker_module
import cops.web_api.worker_broker as broker_module
import cops.web_api.worker_replay as replay_module
from cops.adapters import ToolAdapterRegistry
from cops.contracts import ActionPlan
from cops.evidence.canonical import digest
from cops.execution.authorization import AuthorizationError
from cops.execution.cleanup import CleanupPersistenceError
from cops.execution.credentials import CredentialGrant
from cops.execution.egress import BROKER_FD_ENV
from cops.execution.process import BoundedProcessResult, run_bounded_process
from cops.web_api.worker_broker import DISPATCH_TRIGGER
from tests.auth_testkit import TestExecutionSandbox
from tests.cancellation_testkit import assert_processes_terminated
from tests.test_adapter_execution import _approval_control, _fake_worker, _sandbox
from tests.test_scoped_credentials import RecordingProvider
from tests.test_web_api_replay_envelope import envelope_value, seal
from tests.test_web_api_worker_qualification import _plan


def _configured_worker(tmp_path, monkeypatch, plan, **kwargs):
    worker, authorization_id = _fake_worker(tmp_path, plan, **kwargs)
    adapter = ToolAdapterRegistry().get_adapter(replay_module.WEB_API_REPLAY_TOOL)
    adapter.supported_environments.append("darwin")
    worker.adapter_registry.register_adapter(adapter)
    worker.scope_guard = SimpleNamespace(
        scope=SimpleNamespace(egress_allowed=True),
        check_destination=lambda _: None,
    )
    monkeypatch.setattr(worker_module, "LinuxBubblewrapSandbox", TestExecutionSandbox)
    monkeypatch.setattr(worker_module, "verify_executable_launch_support", lambda: None)
    monkeypatch.setattr(
        worker_module,
        "prepare_executable",
        lambda *_args, **_kwargs: SimpleNamespace(
            invocation_path=sys.executable,
            pass_fds=(),
            remove=lambda: None,
        ),
    )
    return worker, authorization_id


def test_frozen_action_plan_policy_matches_exact_envelope():
    plan = _plan(envelope_value())
    assert isinstance(plan.operations[0]["egress_policy"]["web_api_replay"]["request_urls"], tuple)
    assert replay_module.validate_web_api_operation(plan.operations[0]).request["method"] == "GET"


def test_worker_keeps_credentials_and_body_on_trusted_broker_boundary(tmp_path, monkeypatch):
    value = envelope_value()
    value["credential_references"] = [{"reference": "credential-one", "header": "Authorization"}]
    plan_value = _plan(seal(value)).to_dict()
    plan_value.pop("schema_version")
    plan_value.pop("plan_digest")
    plan_value["credential_references"] = ["credential-one"]
    plan = ActionPlan.create(**plan_value)
    operation = plan.to_dict()["operations"][0]
    secret = "supervisor-only-credential-canary"
    body = "response-body-canary"
    grant = CredentialGrant(
        reference="credential-one",
        environment_variable="COPS_CREDENTIAL_API",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="test-worker-01",
        target=plan.target,
        step_id="step-replay",
        tool=operation["tool"],
        tool_version=operation["tool_version"],
        action="replay",
        operation_index=0,
        operation_digest=digest(operation),
    )
    worker, authorization_id = _configured_worker(
        tmp_path,
        monkeypatch,
        plan,
        credential_provider=RecordingProvider(secret),
        credential_grants=[grant],
    )
    control = _approval_control(worker)

    class Mediator:
        def __init__(self, **kwargs):
            self.envelope = kwargs["envelope"]
            self.plan_digest = kwargs["plan_digest"]
            self.approval_digest = kwargs["approval_digest"]
            self.resolver = kwargs["credential_resolver"]
            assert control.consume_calls == [(authorization_id, plan.plan_id, worker.config.worker_id)]

        def dispatch(
            self,
            approved,
            *,
            plan_digest,
            approval_digest,
            cancellation_event,
            dispatch_observer=None,
        ):
            assert approved == self.envelope.to_dict()
            assert plan_digest == self.plan_digest and approval_digest == self.approval_digest
            assert self.resolver("credential-one", "session-one", "reader") == secret
            assert not cancellation_event.is_set()
            if dispatch_observer is not None:
                dispatch_observer()
            return {"response": {"body": body}}

    monkeypatch.setattr(replay_module, "WebApiReplayMediator", Mediator)

    def run_child(command, **kwargs):
        assert kwargs["operation_env"].keys() == {BROKER_FD_ENV}
        assert kwargs["pass_fds"] == ()
        assert len(kwargs["capability_fds"]) == 1
        assert secret not in repr(command) + repr(kwargs["env"]) + repr(kwargs["operation_env"])
        completed = subprocess.run(
            command,
            env={**kwargs["env"], **kwargs["operation_env"]},
            pass_fds=kwargs["capability_fds"],
            capture_output=True,
            timeout=kwargs["timeout_seconds"],
            check=False,
        )
        assert json.loads(completed.stdout) == {"status": "completed"}
        assert body.encode() not in completed.stdout and secret.encode() not in completed.stdout
        return BoundedProcessResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            timed_out=False,
            output_limit_exceeded=False,
        )

    _sandbox(worker).run_callback = run_child
    execution = worker.execute_plan_with_receipt(
        plan,
        authorization_id=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )
    assert execution.result.status == "success", execution.result.to_dict()
    assert execution.operation_outputs == {"step-replay": {"response": {"body": body}}}
    assert execution.attempted_operation_ids == ("step-replay",)
    assert body not in json.dumps(execution.result.to_dict())
    for path in (tmp_path / "workspace").rglob("*"):
        if path.is_file():
            assert body.encode() not in path.read_bytes()
            assert secret.encode() not in path.read_bytes()
    assert control.store.get_authorization(authorization_id).status == "consumed"
    with pytest.raises(CleanupPersistenceError, match="already contains execution run"):
        worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")
    assert len(control.consume_calls) == 1
    with pytest.raises(AuthorizationError, match="status: consumed"):
        control.consume_authorization(authorization_id, plan, worker.config.worker_id)


def test_worker_propagates_cancellation_without_returning_replay_output(tmp_path, monkeypatch):
    plan = _plan(envelope_value())
    worker, authorization_id = _configured_worker(tmp_path, monkeypatch, plan)
    event = threading.Event()

    class Broker:
        def __init__(self, mediator):
            pass

        @contextmanager
        def open_channel(self, *, deadline, cancellation_event):
            assert cancellation_event is event
            assert deadline > 0
            event.set()
            yield SimpleNamespace(
                environment={BROKER_FD_ENV: "71"},
                pass_fds=(71,),
                result={"body": "discard"},
                dispatch_state=broker_module.DISPATCH_COMPLETED,
            )

    monkeypatch.setattr(broker_module, "WebApiReplayBroker", Broker)
    execution = worker.execute_plan_with_receipt(
        plan,
        authorization_id=authorization_id,
        workspace_dir=tmp_path / "workspace",
        cancellation_event=event,
    )
    assert execution.result.status == "uncertain"
    assert execution.operation_outputs == {}
    assert execution.attempted_operation_ids == ("step-replay",)


def test_completed_dispatch_with_adapter_exit_failure_is_uncertain(tmp_path, monkeypatch):
    value = envelope_value()
    value["request"]["method"] = "POST"
    plan = _plan(seal(value))
    worker, authorization_id = _configured_worker(tmp_path, monkeypatch, plan)

    class Mediator:
        def __init__(self, **kwargs):
            self.envelope = kwargs["envelope"]
            self.plan_digest = kwargs["plan_digest"]
            self.approval_digest = kwargs["approval_digest"]

        def dispatch(
            self,
            approved,
            *,
            plan_digest,
            approval_digest,
            cancellation_event,
            dispatch_observer=None,
        ):
            assert approved == self.envelope.to_dict()
            assert plan_digest == self.plan_digest and approval_digest == self.approval_digest
            assert not cancellation_event.is_set()
            if dispatch_observer is not None:
                dispatch_observer()
            return {"response": {"status": 204}}

    monkeypatch.setattr(replay_module, "WebApiReplayMediator", Mediator)

    def fail_after_completion(command, **kwargs):
        completed = subprocess.run(
            command,
            env={**kwargs["env"], **kwargs["operation_env"]},
            pass_fds=kwargs["capability_fds"],
            capture_output=True,
            timeout=kwargs["timeout_seconds"],
            check=False,
        )
        assert completed.returncode == 0
        assert json.loads(completed.stdout) == {"status": "completed"}
        return BoundedProcessResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=1,
            timed_out=False,
            output_limit_exceeded=False,
        )

    _sandbox(worker).run_callback = fail_after_completion
    execution = worker.execute_plan_with_receipt(
        plan,
        authorization_id=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert execution.result.status == "uncertain"
    assert "automatic repeat disallowed" in execution.result.status_details["reason"]
    assert execution.operation_outputs == {}
    assert execution.attempted_operation_ids == ("step-replay",)


def test_cancellation_after_broker_completion_terminates_adapter_child(tmp_path, monkeypatch):
    plan = _plan(envelope_value())
    worker, authorization_id = _configured_worker(tmp_path, monkeypatch, plan)
    cancellation_event = threading.Event()
    child_pid_path = tmp_path / "adapter-child.pid"
    broker_complete_path = tmp_path / "broker-complete"
    watcher_failures = []

    class Mediator:
        def __init__(self, **kwargs):
            self.envelope = kwargs["envelope"]
            self.plan_digest = kwargs["plan_digest"]
            self.approval_digest = kwargs["approval_digest"]

        def dispatch(
            self,
            _approved,
            *,
            plan_digest,
            approval_digest,
            cancellation_event,
            dispatch_observer=None,
        ):
            assert plan_digest and approval_digest
            assert not cancellation_event.is_set()
            if dispatch_observer is not None:
                dispatch_observer()
            return {"response": {"status": 204}}

    monkeypatch.setattr(replay_module, "WebApiReplayMediator", Mediator)

    child_script = f"""
import os
import socket
import sys
import time

with open(sys.argv[1], "w", encoding="ascii") as stream:
    stream.write(str(os.getpid()))
channel = socket.socket(fileno=int(os.environ[{BROKER_FD_ENV!r}]))
channel.sendall({DISPATCH_TRIGGER!r})
response = bytearray()
while not response.endswith(b"\\n"):
    chunk = channel.recv(65536)
    if not chunk:
        raise RuntimeError("broker closed before completion")
    response.extend(chunk)
with open(sys.argv[2], "w", encoding="ascii") as stream:
    stream.write("complete")
while True:
    time.sleep(60)
"""

    def run_hanging_child(_command, **kwargs):
        assert kwargs["cancellation_event"] is cancellation_event

        def cancel_after_broker_completion():
            deadline = time.monotonic() + 5
            while not broker_complete_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not broker_complete_path.exists():
                watcher_failures.append("broker completion marker was not written")
            cancellation_event.set()

        watcher = threading.Thread(target=cancel_after_broker_completion, daemon=True)
        watcher.start()
        result = run_bounded_process(
            [sys.executable, "-c", child_script, str(child_pid_path), str(broker_complete_path)],
            cwd=kwargs["cwd"],
            env={**kwargs["env"], **kwargs["operation_env"]},
            timeout_seconds=min(10, kwargs["timeout_seconds"]),
            max_output_bytes=kwargs["max_output_bytes"],
            pass_fds=kwargs["capability_fds"],
            cancellation_event=cancellation_event,
        )
        watcher.join(timeout=5)
        assert not watcher.is_alive()
        return result

    _sandbox(worker).run_callback = run_hanging_child
    started = time.monotonic()
    execution = worker.execute_plan_with_receipt(
        plan,
        authorization_id=authorization_id,
        workspace_dir=tmp_path / "workspace",
        cancellation_event=cancellation_event,
    )

    assert time.monotonic() - started < 8
    assert watcher_failures == []
    assert broker_complete_path.read_text(encoding="ascii") == "complete"
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    assert_processes_terminated({child_pid})
    assert execution.result.status == "uncertain"
    assert execution.operation_outputs == {}
    assert execution.attempted_operation_ids == ("step-replay",)
    assert _sandbox(worker).run_calls[0]["cancellation_event"] is cancellation_event


def test_broker_proven_non_dispatch_is_failed_not_uncertain(tmp_path, monkeypatch):
    value = envelope_value()
    value["request"]["method"] = "POST"
    plan = _plan(seal(value))
    worker, authorization_id = _configured_worker(tmp_path, monkeypatch, plan)

    def fail_before_trigger(_command, **_kwargs):
        raise RuntimeError("adapter launch failed before broker trigger")

    _sandbox(worker).run_callback = fail_before_trigger
    execution = worker.execute_plan_with_receipt(
        plan,
        authorization_id=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert execution.result.status == "failed"
    assert execution.operation_outputs == {}
    assert execution.attempted_operation_ids == ()


@pytest.mark.parametrize("cancel_during_pacing", [False, True])
def test_worker_owns_approved_replay_pacing(tmp_path, monkeypatch, cancel_during_pacing):
    value = envelope_value()
    value["budgets"]["rate_limit_rps"] = 20
    plan_value = _plan(value).to_dict()
    plan_value.pop("schema_version")
    plan_value.pop("plan_digest")
    second = deepcopy(plan_value["operations"][0])
    second["step_id"] = "step-second"
    plan_value["operations"].append(second)
    plan_value["batch"]["max_operations"] = 2
    plan = ActionPlan.create(**plan_value)
    worker, authorization_id = _configured_worker(tmp_path, monkeypatch, plan)
    event = threading.Event()
    dispatches = []
    timer = None

    class Broker:
        def __init__(self, mediator):
            pass

        @contextmanager
        def open_channel(self, *, deadline, cancellation_event):
            nonlocal timer
            dispatches.append(time.monotonic())
            if cancel_during_pacing:
                timer = threading.Timer(0.01, event.set)
                timer.start()
            yield SimpleNamespace(
                environment={BROKER_FD_ENV: "71"},
                pass_fds=(71,),
                result={"ok": True},
                dispatch_state=broker_module.DISPATCH_COMPLETED,
            )

    monkeypatch.setattr(broker_module, "WebApiReplayBroker", Broker)
    try:
        execution = worker.execute_plan_with_receipt(
            plan,
            authorization_id=authorization_id,
            workspace_dir=tmp_path / "workspace",
            cancellation_event=event,
        )
    finally:
        if timer is not None:
            timer.join()
    if cancel_during_pacing:
        assert execution.result.status == "cancelled"
        assert "pacing" in execution.result.status_details["reason"]
        assert len(dispatches) == 1
        assert set(execution.operation_outputs) == {"step-replay"}
        assert execution.attempted_operation_ids == ("step-replay",)
    else:
        assert execution.result.status == "success", execution.result.to_dict()
        assert len(dispatches) == 2
        assert dispatches[1] - dispatches[0] >= 0.05
        assert set(execution.operation_outputs) == {"step-replay", "step-second"}
        assert execution.attempted_operation_ids == ("step-replay", "step-second")


@pytest.mark.parametrize(
    "legacy_tool",
    [
        "cops.web_api.standard-http-replayer",
        "cops.web_api.bounded-websocket-replayer",
    ],
)
def test_legacy_replay_cannot_consume_approval(tmp_path, monkeypatch, legacy_tool):
    value = _plan(envelope_value()).to_dict()
    value.pop("schema_version")
    value.pop("plan_digest")
    value["operations"][0]["tool"] = legacy_tool
    value["operations"][0].pop("egress_policy")
    plan = ActionPlan.create(**value)
    worker, authorization_id = _configured_worker(tmp_path, monkeypatch, plan)
    with pytest.raises(worker_module.WorkerExecutionError, match="legacy"):
        worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")
    assert _approval_control(worker).consume_calls == []
