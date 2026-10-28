"""Portable qualification of Web API plans through the approval/worker boundary.

These contracts use simulated authority transport and a sandbox double. They do
not establish Linux account, namespace, descriptor, or network isolation.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from cops.adapters.registry import ToolActionDefinition
from cops.contracts import ActionPlan
from cops.execution import ApprovalStore
from cops.execution.control import (
    REQUEST_SCHEMA,
    ApprovalControlClient,
    ApprovalControlError,
    _ApprovalControlTransportError,
)
from cops.execution.credentials import ScopedCredentialResolver
from cops.execution.egress import BROKER_FD_ENV
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.web_api.worker_broker import DISPATCH_TRIGGER, MAX_BROKER_RESPONSE_BYTES
from cops.web_api.worker_replay import WEB_API_REPLAY_TOOL, validate_web_api_operation
from tests import test_web_api_replay_envelope as replay_fixtures
from tests.auth_testkit import make_test_approval_authority
from tests.test_approval_authority_qualification import _exchange_response, _worker
from tests.test_scoped_credentials import _grant
from tests.test_web_api_replay_envelope import (
    envelope_value,
    laboratory_value,
    operation,
    seal,
)

bounded_http_lab = replay_fixtures.bounded_http_lab


def _plan(envelope: dict) -> ActionPlan:
    fixture = Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json"
    document = json.loads(fixture.read_text(encoding="utf-8"))
    document.pop("schema_version")
    document.pop("plan_digest")
    document["operations"] = [{
        **operation(envelope), "step_id": "step-replay", "timeout_seconds": 5,
        "idempotent": False,
    }]
    document["credential_references"] = [item["reference"] for item in envelope["credential_references"]]
    document["limits"]["egress_allowed"] = True
    return ActionPlan.create(**document)


def _consume(authority, authorization, plan):
    return authority.consume_document(
        {
            "schema_version": REQUEST_SCHEMA, "request_id": str(uuid.uuid4()),
            "operation": "consume", "authorization_id": authorization.authorization_id,
            "worker_identity": "worker-01", "action_plan": plan.to_dict(),
        },
        peer_pid=authority.worker_pid, peer_uid=authority.worker_uid, peer_gid=authority.worker_gid,
    )


def _consumption_count(authority) -> int:
    with sqlite3.connect(authority.store.db_path) as connection:
        return connection.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0]


@pytest.mark.parametrize("binding", ["session_id", "role_id"])
def test_actual_envelope_context_change_cannot_consume_original_approval(tmp_path, monkeypatch, binding):
    # Simulate authority readiness only; production peer isolation is Linux-only.
    monkeypatch.setattr("cops.execution.control.sys_platform_linux", lambda: True)
    approved_plan = _plan(envelope_value())
    authority, authorization, _ = make_test_approval_authority(tmp_path, approved_plan)
    changed = envelope_value()
    changed[binding] = "different-context"
    # Resealing and rebuilding removes malformed input as a rejection reason:
    # the authority must reject a valid envelope bound to a different plan.
    changed_plan = _plan(seal(changed))
    validate_web_api_operation(changed_plan.to_dict()["operations"][0])
    assert changed_plan.plan_digest != approved_plan.plan_digest

    with pytest.raises(ApprovalControlError):
        _consume(authority, authorization, changed_plan)

    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"
    assert _consumption_count(authority) == 0
    assert _consume(authority, authorization, approved_plan)["ok"] is True
    assert _consumption_count(authority) == 1


class _ParentProvider:
    def __init__(self):
        self.references = []

    def resolve(self, reference, *, deadline):
        assert deadline > 0
        self.references.append(reference)
        return "qualification-private-canary"


def _replay_worker(tmp_path, authority, plan, monkeypatch, suffix, *, provider=None):
    worker, sandbox = _worker(tmp_path, authority, plan, monkeypatch, suffix)
    adapter = worker.adapter_registry.get_adapter("qualification-tool")
    worker.adapter_registry.register_adapter(replace(
        adapter, tool=WEB_API_REPLAY_TOOL, version="1",
        actions={"replay": ToolActionDefinition(
            action="replay", description="Invoke the fixed replay capability", base_args=[], parameters={},
        )},
    ))
    # A portable construction contract, not Linux sandbox qualification.
    monkeypatch.setattr("cops.execution.worker.LinuxBubblewrapSandbox", type(sandbox))
    worker.scope_guard = ScopeGuard(ScopeDefinition(
        included_ips={ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address(plan.target)},
        egress_allowed=True,
    ))
    if provider is not None:
        worker.credential_resolver = ScopedCredentialResolver(
            provider, [_grant(plan, worker_identity="worker-01")], approval_control=worker.approval_control,
        )

    def dispatch(_command, *, operation_env, capability_fds, **_kwargs):
        assert set(operation_env) == {BROKER_FD_ENV}
        assert capability_fds == (int(operation_env[BROKER_FD_ENV]),)
        with socket.fromfd(capability_fds[0], socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            assert channel.family == socket.AF_UNIX
            assert channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
            channel.settimeout(3)
            channel.sendall(DISPATCH_TRIGGER)
            response = bytearray()
            while not response.endswith(b"\n"):
                part = channel.recv(min(65536, MAX_BROKER_RESPONSE_BYTES + 1 - len(response)))
                assert part, "broker closed without a bounded response"
                response.extend(part)
                assert len(response) <= MAX_BROKER_RESPONSE_BYTES
            assert "error" not in json.loads(response)
        return sandbox.result

    sandbox.run_callback = dispatch
    return worker, sandbox


@pytest.fixture
def replay_authority(tmp_path, monkeypatch):
    monkeypatch.setattr("cops.execution.control.sys_platform_linux", lambda: True)
    monkeypatch.setattr(ApprovalControlClient, "assert_ready", lambda self, worker_identity: None)

    def provision(plan):
        authority, authorization, _ = make_test_approval_authority(tmp_path, plan)
        monkeypatch.setattr(
            ApprovalControlClient, "_exchange", lambda self, request: _exchange_response(authority, request),
        )
        return authority, authorization

    return provision


@pytest.mark.parametrize("binding", ["session_id", "role_id"])
def test_worker_rejects_changed_context_before_provider_or_network(
    tmp_path, monkeypatch, bounded_http_lab, replay_authority, binding,
):
    url, seen, _ = bounded_http_lab
    approved = laboratory_value(url + "/items")
    approved["credential_references"] = [{"reference": "service-token", "header": "Authorization"}]
    approved_plan = _plan(seal(approved))
    authority, authorization = replay_authority(approved_plan)
    changed = json.loads(json.dumps(approved))
    changed[binding] = "different-context"
    changed_plan = _plan(seal(changed))
    provider = _ParentProvider()
    worker, sandbox = _replay_worker(
        tmp_path, authority, changed_plan, monkeypatch, binding, provider=provider,
    )

    with pytest.raises(ApprovalControlError):
        worker.execute_plan_with_receipt(changed_plan, authorization_id=authorization.authorization_id)

    assert provider.references == []
    assert sandbox.run_calls == []
    assert seen == []
    assert _consumption_count(authority) == 0
    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"


def test_receipt_digests_and_only_broker_capability_reach_worker_dispatch(
    tmp_path, monkeypatch, bounded_http_lab, replay_authority,
):
    from cops.web_api import worker_replay

    url, seen, _ = bounded_http_lab
    value = laboratory_value(url + "/items")
    value["credential_references"] = [{"reference": "service-token", "header": "Authorization"}]
    plan = _plan(seal(value))
    authority, authorization = replay_authority(plan)
    provider = _ParentProvider()
    worker, sandbox = _replay_worker(tmp_path, authority, plan, monkeypatch, "binding", provider=provider)
    mediator_arguments = []
    original = worker_replay.WebApiReplayMediator

    def mediator(**kwargs):
        mediator_arguments.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(worker_replay, "WebApiReplayMediator", mediator)
    execution = worker.execute_plan_with_receipt(plan, authorization_id=authorization.authorization_id)

    assert execution.result.status == "success"
    assert len(mediator_arguments) == 1
    assert mediator_arguments[0]["plan_digest"] == execution.approval_receipt.plan_digest == plan.plan_digest
    assert mediator_arguments[0]["approval_digest"] == execution.approval_receipt.authorization_digest
    assert mediator_arguments[0]["envelope"].to_dict() == value
    assert provider.references == ["service-token"]
    assert len(seen) == len(sandbox.run_calls) == _consumption_count(authority) == 1
    assert seen[0][2]["Authorization"] == "qualification-private-canary"
    assert execution.operation_outputs["step-replay"]["status"] == 200
    assert execution.operation_outputs["step-replay"]["body"] == "ok"
    call = sandbox.run_calls[0]
    assert call["command"] == ("/proc/self/fd/7",)
    assert call["pass_fds"] == ()
    assert set(call["operation_env"]) == {BROKER_FD_ENV}
    assert call["capability_fds"] == (int(call["operation_env"][BROKER_FD_ENV]),)
    child_inputs = json.dumps({key: call[key] for key in ("command", "env", "operation_env")})
    for private in ("qualification-private-canary", "service-token", value["session_id"], value["role_id"],
                    value["request_digest"], plan.plan_digest, execution.approval_receipt.authorization_digest, url):
        assert private not in child_inputs


@pytest.mark.parametrize("response_loss", [False, True], ids=["concurrent-double-spend", "lost-response-retry"])
def test_approval_retries_produce_exactly_one_web_api_exchange(
    tmp_path, monkeypatch, bounded_http_lab, replay_authority, response_loss,
):
    url, seen, _ = bounded_http_lab
    plan = _plan(laboratory_value(url + "/items"))
    authority, authorization = replay_authority(plan)
    request_ids = []
    barrier = threading.Barrier(2, timeout=10)

    def exchange(self, request):
        request_ids.append(request["request_id"])
        if not response_loss:
            barrier.wait()
        reopened = replace(authority, store=ApprovalStore(authority.store.db_path))
        response = _exchange_response(reopened, request)
        if response_loss and len(request_ids) == 1:
            raise _ApprovalControlTransportError("injected response loss after durable commit")
        return response

    monkeypatch.setattr(ApprovalControlClient, "_exchange", exchange)
    workers = [_replay_worker(tmp_path, authority, plan, monkeypatch, str(index)) for index in range(2)]
    if response_loss:
        outcomes = [workers[0][0].execute_plan_with_receipt(plan, authorization_id=authorization.authorization_id)]
        assert len(request_ids) == 2 and request_ids[0] == request_ids[1]
    else:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(worker.execute_plan_with_receipt, plan,
                                       authorization_id=authorization.authorization_id) for worker, _ in workers]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=15))
                except ApprovalControlError as error:
                    outcomes.append(error)
        assert len(set(request_ids)) == 2
        assert sum(isinstance(item, ApprovalControlError) for item in outcomes) == 1
    completed = [item.result for item in outcomes if not isinstance(item, ApprovalControlError)]
    assert [item.status for item in completed] == ["success"], [
        {"status": item.status, "status_details": item.status_details} for item in completed
    ]
    assert len(seen) == sum(len(sandbox.run_calls) for _, sandbox in workers) == _consumption_count(authority) == 1

    # A new request is a replay, not a recovery of the original request id.
    monkeypatch.setattr(ApprovalControlClient, "_exchange", lambda self, request: _exchange_response(authority, request))
    replay, replay_sandbox = _replay_worker(tmp_path, authority, plan, monkeypatch, "fresh-replay")
    with pytest.raises(ApprovalControlError):
        replay.execute_plan_with_receipt(plan, authorization_id=authorization.authorization_id)
    assert replay_sandbox.run_calls == []
    assert len(seen) == _consumption_count(authority) == 1
