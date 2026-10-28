"""Typed laboratory capabilities expose no caller-selected execution channel."""

import json
import multiprocessing
import os
import socket
import subprocess
import sys
import threading
from time import monotonic
from types import MappingProxyType

import pytest

from cops.adapters import AdapterParameterError, ToolAdapterRegistry
from cops.evidence.canonical import digest
from cops.execution.egress import BROKER_FD_ENV
from cops.laboratory.agent_mcp_broker import (
    DISPATCH_ATTEMPTED_UNCERTAIN,
    DISPATCH_COMPLETED,
    DISPATCH_NOT_DISPATCHED,
    DISPATCH_TRIGGER,
    AgentMcpBroker,
)
from cops.laboratory.agent_mcp_worker import (
    AGENT_MCP_TOOL,
    ENVELOPE_VERSION,
    RESULT_VERSION,
    AgentMcpEnvelope,
    AgentMcpError,
    AgentMcpMediator,
    validate_agent_mcp_operation,
)

PLAN = "a" * 64
APPROVAL = "b" * 64
SECRET = "Bearer private-canary-cookie-model-output"


def envelope_data():
    return {
        "schema_version": ENVELOPE_VERSION,
        "engagement_id": "engagement-1",
        "scenario_id": "scenario-1",
        "session_id": "session-1",
        "role_id": "role-1",
        "tenant_id": "tenant-1",
        "case_id": "case-1",
        "dispatcher_id": "agent-mcp-stdio-v1",
        "request_digest": "c" * 64,
        "scenario_digest": "d" * 64,
        "limits": {"max_duration_seconds": 2, "max_output_bytes": 4096},
    }


def operation():
    return {
        "tool": AGENT_MCP_TOOL,
        "tool_version": "1",
        "action": "run",
        "idempotent": False,
        "arguments": {"envelope": envelope_data()},
        "egress_policy": {},
    }


class Dispatcher:
    def __init__(self, *, fail=False, block=False):
        self.calls = multiprocessing.get_context("fork").Value("i", 0)
        self.fail = fail
        self.block = block
        self.cancelled = threading.Event()

    def __call__(self, envelope, *, deadline, cancellation_event, dispatch_context):
        self.calls.value += 1
        assert envelope == envelope_data()
        assert deadline > monotonic()
        assert dict(dispatch_context) == {
            "plan_digest": PLAN,
            "approval_digest": APPROVAL,
            "envelope_digest": digest(envelope),
        }
        with pytest.raises(TypeError):
            dispatch_context["plan_digest"] = "e" * 64
        if self.block:
            cancellation_event.wait(2)
            self.cancelled.set()
        if self.fail:
            raise ValueError(SECRET)
        return {
            "status": "completed",
            "cleanup": {"verified": True},
            "model_output": SECRET,
            "response": {"cookie": SECRET},
            "canary": SECRET,
        }


def mediator(dispatcher=None, data=None):
    return AgentMcpMediator(
        envelope=AgentMcpEnvelope.from_dict(data or envelope_data()),
        plan_digest=PLAN,
        approval_digest=APPROVAL,
        dispatcher=dispatcher or Dispatcher(),
    )


def dispatch(subject, **kwargs):
    return subject.dispatch(subject.envelope.to_dict(), plan_digest=PLAN, approval_digest=APPROVAL, **kwargs)


def test_validated_envelope_detaches_frozen_plan_and_exports():
    data = envelope_data()
    data["limits"] = MappingProxyType(data["limits"])
    envelope = AgentMcpEnvelope.from_dict(MappingProxyType(data))
    detached = envelope.to_dict()
    detached["limits"]["max_output_bytes"] = 1
    assert envelope.to_dict() == envelope_data()
    assert envelope.digest == digest(envelope_data())
    assert validate_agent_mcp_operation(operation()).digest == envelope.digest
    with pytest.raises(AttributeError):
        envelope._canonical_json = b"{}"
    with pytest.raises(TypeError):
        AgentMcpEnvelope(b"{}")


@pytest.mark.parametrize(
    "field",
    ["command", "binary", "url", "destinations", "transport", "credentials", "authorization", "cookie", "request"],
)
def test_envelope_rejects_every_execution_or_secret_extension(field):
    data = envelope_data()
    data[field] = SECRET
    with pytest.raises(AgentMcpError):
        AgentMcpEnvelope.from_dict(data)


@pytest.mark.parametrize("field", list(envelope_data()))
def test_envelope_requires_every_binding(field):
    data = envelope_data()
    del data[field]
    with pytest.raises(AgentMcpError):
        AgentMcpEnvelope.from_dict(data)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), object(), b"secret"])
def test_envelope_rejects_non_json_and_nonfinite_values(value):
    data = envelope_data()
    data["limits"]["max_duration_seconds"] = value
    with pytest.raises(AgentMcpError):
        AgentMcpEnvelope.from_dict(data)


@pytest.mark.parametrize("value", [True, 0, -1, 301, 1.5])
def test_duration_limits_are_bounded_integers(value):
    data = envelope_data()
    data["limits"]["max_duration_seconds"] = value
    with pytest.raises(AgentMcpError):
        AgentMcpEnvelope.from_dict(data)


@pytest.mark.parametrize(
    "field", ["plan_digest", "approval_digest", "case_id", "request_digest", "scenario_digest", "dispatcher_id"]
)
def test_mismatched_binding_never_dispatches_or_consumes(field):
    recorder = Dispatcher()
    subject = mediator(recorder)
    data = subject.envelope.to_dict()
    bindings = {"plan_digest": PLAN, "approval_digest": APPROVAL}
    if field in bindings:
        bindings[field] = "e" * 64
    else:
        data[field] = "e" * 64 if field.endswith("digest") else "other"
    with pytest.raises(AgentMcpError, match="binding mismatch"):
        subject.dispatch(data, **bindings)
    assert recorder.calls.value == 0
    assert dispatch(subject)["status"] == "completed"


def test_only_digest_metadata_survives_dispatch_and_capability_is_single_use():
    recorder = Dispatcher()
    subject = mediator(recorder)
    result = dispatch(subject)
    assert set(result) == {
        "schema_version",
        "status",
        "envelope_digest",
        "plan_digest",
        "approval_digest",
        "result_digest",
        "result_bytes",
    }
    assert result["schema_version"] == RESULT_VERSION
    assert result["envelope_digest"] == digest(envelope_data())
    assert SECRET not in json.dumps(result)
    assert result["plan_digest"] == PLAN and result["approval_digest"] == APPROVAL
    with pytest.raises(AttributeError):
        subject.plan_digest = "e" * 64
    with pytest.raises(AgentMcpError, match="consumed"):
        dispatch(subject)
    assert recorder.calls.value == 1


@pytest.mark.parametrize("kind", ["cancelled", "expired"])
def test_pre_dispatch_cancellation_and_deadline_prevent_effect(kind):
    recorder = Dispatcher()
    event = threading.Event()
    if kind == "cancelled":
        event.set()
    with pytest.raises(AgentMcpError):
        dispatch(
            mediator(recorder), cancellation_event=event, deadline=monotonic() + (2 if kind == "cancelled" else -1)
        )
    assert recorder.calls.value == 0


def test_inflight_deadline_signals_cooperative_dispatcher():
    recorder = Dispatcher(block=True)
    started = monotonic()
    with pytest.raises(AgentMcpError, match="deadline"):
        dispatch(mediator(recorder), deadline=monotonic() + 0.05)
    assert monotonic() - started < 1
    assert recorder.cancelled.wait(1)


def test_inflight_cancellation_signals_cooperative_dispatcher():
    recorder = Dispatcher(block=True)
    event = threading.Event()
    timer = threading.Timer(0.05, event.set)
    timer.start()
    try:
        with pytest.raises(AgentMcpError, match="cancelled"):
            dispatch(mediator(recorder), cancellation_event=event)
        assert recorder.cancelled.wait(1)
    finally:
        timer.cancel()
        timer.join()


@pytest.mark.parametrize(
    "field,value",
    [("max_output_bytes", 0), ("max_output_bytes", 2097153), ("max_output_bytes", True), ("transport", "stdio")],
)
def test_output_budget_and_unknown_nested_fields_fail_closed(field, value):
    data = envelope_data()
    data["limits"][field] = value
    with pytest.raises(AgentMcpError):
        AgentMcpEnvelope.from_dict(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "cops.agent-mcp-laboratory-envelope/v0"),
        ("dispatcher_id", "/tmp/executable"),
        ("scenario_id", "https://attacker.test"),
        ("request_digest", "A" * 64),
        ("scenario_digest", "not-a-digest"),
    ],
)
def test_versions_paths_destinations_and_malformed_digests_fail_closed(field, value):
    data = envelope_data()
    data[field] = value
    with pytest.raises(AgentMcpError):
        AgentMcpEnvelope.from_dict(data)


@pytest.mark.parametrize("result", ["x" * 4097, {"secret": float("nan")}, object()])
def test_dispatcher_output_is_bounded_finite_json_and_error_is_redacted(result):
    subject = mediator(lambda *args, **kwargs: result)
    with pytest.raises(AgentMcpError, match="failed or exceeded") as error:
        dispatch(subject)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize(
    "receipt",
    [
        {"status": "failed", "cleanup": {"verified": True}},
        {"status": "completed", "cleanup": {"verified": False}},
        {"status": "completed"},
    ],
)
def test_dispatcher_receipt_must_confirm_completion_and_cleanup(receipt):
    subject = mediator(lambda *args, **kwargs: receipt)
    with pytest.raises(AgentMcpError, match="failed or exceeded"):
        dispatch(subject)


def test_operation_rejects_egress_and_arbitrary_arguments():
    for key, value in (
        ("egress_policy", {"network": True}),
        ("arguments", {"envelope": envelope_data(), "command": "id"}),
        ("idempotent", True),
    ):
        data = operation()
        data[key] = value
        with pytest.raises(AgentMcpError):
            validate_agent_mcp_operation(data)


def test_fixed_registered_adapter_receives_only_completion(monkeypatch):
    adapter = ToolAdapterRegistry().get_adapter(AGENT_MCP_TOOL)
    with monkeypatch.context() as patch:
        patch.setattr("cops.adapters.registry.sys.platform", "linux")
        command = adapter.assemble_command("run", {})
        assert command[1:3] == ["-I", "-c"]
        with pytest.raises(AdapterParameterError):
            adapter.assemble_command("run", {"envelope": envelope_data()})
    recorder = Dispatcher()
    broker = AgentMcpBroker(mediator(recorder))
    with broker.open_channel(deadline=monotonic() + 5) as channel:
        assert set(channel.environment) == {BROKER_FD_ENV}
        assert tuple(map(int, channel.environment.values())) == channel.pass_fds
        completed = subprocess.run(
            [sys.executable, *command[1:]],
            env=dict(channel.environment),
            pass_fds=channel.pass_fds,
            capture_output=True,
            timeout=3,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert json.loads(completed.stdout) == {"status": "completed"}
        assert completed.stderr == b""
    assert recorder.calls.value == 1
    assert channel.dispatch_state == DISPATCH_COMPLETED
    assert SECRET not in json.dumps(channel.result)
    assert channel.result["envelope_digest"] == digest(envelope_data())
    with pytest.raises(AgentMcpError, match="consumed"):
        with broker.open_channel(deadline=monotonic() + 1):
            pass


@pytest.mark.parametrize(
    "trigger",
    [
        b"{}\n",
        DISPATCH_TRIGGER[:-1] + b" \n",
        DISPATCH_TRIGGER + DISPATCH_TRIGGER,
        b'{"version":"cops.agent-mcp-laboratory/v1","action":"dispatch","request":{}}\n',
    ],
)
def test_expanded_or_malformed_trigger_never_dispatches(trigger):
    recorder = Dispatcher()
    with AgentMcpBroker(mediator(recorder)).open_channel(deadline=monotonic() + 3) as channel:
        with socket.socket(fileno=os.dup(channel.pass_fds[0])) as client:
            client.settimeout(2)
            client.sendall(trigger)
            assert json.loads(client.recv(4096)) == {"error": "laboratory_denied"}
    assert recorder.calls.value == 0
    assert channel.result is None
    assert channel.dispatch_state == DISPATCH_NOT_DISPATCHED


@pytest.mark.parametrize("cancel", [False, True])
def test_idle_broker_cancellation_or_deadline_closes_channel(cancel):
    recorder = Dispatcher()
    event = threading.Event()
    with AgentMcpBroker(mediator(recorder)).open_channel(
        deadline=monotonic() + (2 if cancel else 0.05), cancellation_event=event
    ) as channel:
        with socket.socket(fileno=os.dup(channel.pass_fds[0])) as client:
            client.settimeout(1)
            if cancel:
                event.set()
            assert client.recv(4096) in (b"", b'{"error":"laboratory_denied"}\n')
    assert recorder.calls.value == 0
    assert channel.dispatch_state == DISPATCH_NOT_DISPATCHED


def test_dispatcher_failure_is_redacted_and_classified_uncertain():
    recorder = Dispatcher(fail=True)
    with AgentMcpBroker(mediator(recorder)).open_channel(deadline=monotonic() + 3) as channel:
        with socket.socket(fileno=os.dup(channel.pass_fds[0])) as client:
            client.sendall(DISPATCH_TRIGGER)
            assert json.loads(client.recv(4096)) == {"error": "laboratory_denied"}
    assert recorder.calls.value == 1
    assert channel.result is None
    assert channel.dispatch_state == DISPATCH_ATTEMPTED_UNCERTAIN
