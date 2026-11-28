"""The adapter has one fixed trigger and cannot choose request details."""

import json
import multiprocessing
import os
import socket
import subprocess
import sys
import threading
from time import monotonic, sleep
from types import SimpleNamespace

import pytest

import cops.web_api.worker_broker as broker_module
from cops.adapters import AdapterParameterError, ToolAdapterRegistry
from cops.execution.egress import BROKER_FD_ENV
from cops.web_api.worker_broker import (
    DISPATCH_ATTEMPTED_UNCERTAIN,
    DISPATCH_COMPLETED,
    DISPATCH_NOT_DISPATCHED,
    DISPATCH_TRIGGER,
    WebApiReplayBroker,
)
from cops.web_api.worker_replay import WEB_API_REPLAY_TOOL, WebApiReplayError


class RecordingMediator:
    def __init__(self):
        self.calls = multiprocessing.get_context("fork").Value("i", 0)
        self.envelope = SimpleNamespace(to_dict=lambda: {"owned": True})
        self.plan_digest = "a" * 64
        self.approval_digest = "b" * 64

    def dispatch(
        self,
        value,
        *,
        plan_digest,
        approval_digest,
        cancellation_event,
        dispatch_observer=None,
    ):
        assert value == {"owned": True}
        assert plan_digest == self.plan_digest and approval_digest == self.approval_digest
        assert not cancellation_event.is_set()
        if dispatch_observer is not None:
            dispatch_observer()
        self.calls.value += 1
        return {"response": {"body": "sanitized-result"}}


def _read(channel):
    with socket.socket(fileno=os.dup(channel.pass_fds[0])) as client:
        client.settimeout(2)
        return client.recv(4096)


def test_fixed_registered_adapter_returns_only_broker_result(monkeypatch):
    adapter = ToolAdapterRegistry().get_adapter(WEB_API_REPLAY_TOOL)
    with monkeypatch.context() as patch:
        patch.setattr("cops.adapters.registry.sys.platform", "linux")
        command = adapter.assemble_command("replay", {})
        assert command[1:3] == ["-I", "-c"]
        with pytest.raises(AdapterParameterError):
            adapter.assemble_command("replay", {"envelope": {}})
    mediator = RecordingMediator()
    broker = WebApiReplayBroker(mediator)
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
        assert b"sanitized-result" not in completed.stdout
    assert mediator.calls.value == 1
    assert channel.result == {"response": {"body": "sanitized-result"}}
    assert channel.dispatch_state == DISPATCH_COMPLETED
    with pytest.raises(WebApiReplayError, match="consumed"):
        with broker.open_channel(deadline=monotonic() + 5):
            pass


def test_completed_result_is_finalized_before_dispatch_state(monkeypatch):
    real_loads = broker_module.json.loads

    def delayed_loads(value):
        sleep(0.35)
        return real_loads(value)

    monkeypatch.setattr(broker_module.json, "loads", delayed_loads)
    mediator = RecordingMediator()
    with WebApiReplayBroker(mediator).open_channel(deadline=monotonic() + 3) as channel:
        with socket.socket(fileno=os.dup(channel.pass_fds[0])) as client:
            client.sendall(DISPATCH_TRIGGER)
            assert real_loads(client.recv(4096)) == {"status": "completed"}

    assert channel.result == {"response": {"body": "sanitized-result"}}
    assert channel.dispatch_state == DISPATCH_COMPLETED


@pytest.mark.parametrize(
    "trigger",
    [
        b"{}\n",
        DISPATCH_TRIGGER[:-1] + b" " + b"\n",
        b'{"version":"cops.web-api-replay/v1","action":"dispatch","url":"https://attacker.test"}\n',
        DISPATCH_TRIGGER + DISPATCH_TRIGGER,
    ],
)
def test_unknown_or_expanded_child_trigger_never_dispatches(trigger):
    mediator = RecordingMediator()
    with WebApiReplayBroker(mediator).open_channel(deadline=monotonic() + 3) as channel:
        with socket.socket(fileno=os.dup(channel.pass_fds[0])) as client:
            client.sendall(trigger)
            assert json.loads(client.recv(4096)) == {"error": "replay_denied"}
    assert channel.result is None
    assert mediator.calls.value == 0
    assert channel.dispatch_state == DISPATCH_NOT_DISPATCHED


@pytest.mark.parametrize("cancel", [False, True])
def test_deadline_and_cancellation_close_idle_child_channel(cancel):
    mediator = RecordingMediator()
    event = threading.Event()
    with WebApiReplayBroker(mediator).open_channel(
        deadline=monotonic() + (3 if cancel else 0.1),
        cancellation_event=event,
    ) as channel:
        if cancel:
            event.set()
        assert _read(channel) in (b"", b'{"error":"replay_denied"}\n')
    assert mediator.calls.value == 0
    assert channel.result is None
    assert channel.dispatch_state == DISPATCH_NOT_DISPATCHED


class FailingMediator(RecordingMediator):
    def dispatch(
        self,
        value,
        *,
        plan_digest,
        approval_digest,
        cancellation_event,
        dispatch_observer=None,
    ):
        assert value == {"owned": True}
        assert plan_digest == self.plan_digest and approval_digest == self.approval_digest
        assert not cancellation_event.is_set()
        if dispatch_observer is not None:
            dispatch_observer()
        self.calls.value += 1
        raise WebApiReplayError("response dropped after dispatch")


def test_post_dispatch_failure_is_reported_as_uncertain():
    mediator = FailingMediator()
    with WebApiReplayBroker(mediator).open_channel(deadline=monotonic() + 3) as channel:
        with socket.socket(fileno=os.dup(channel.pass_fds[0])) as client:
            client.sendall(DISPATCH_TRIGGER)
            assert json.loads(client.recv(4096)) == {"error": "replay_denied"}

    assert channel.result is None
    assert mediator.calls.value == 1
    assert channel.dispatch_state == DISPATCH_ATTEMPTED_UNCERTAIN
