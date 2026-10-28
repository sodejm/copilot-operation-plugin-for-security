"""Portable authority/worker contracts; these do not qualify Linux OS isolation.

The real verifier, durable store, client retry logic, and worker execute here.
Peer credentials and transport are simulated, and adapter dispatch is counted
by a sandbox double. Real account/namespace qualification remains Linux-only.
"""

from __future__ import annotations

import json
import multiprocessing
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from cops.adapters import ExecutableVerification, ToolActionDefinition, ToolAdapter, ToolAdapterRegistry
from cops.contracts import ActionPlan
from cops.execution import ApprovalStore, IsolatedWorker
from cops.execution.authorization import (
    AuthorizationTrustStore,
    TrustedAuthorizationKey,
    create_execution_authorization,
)
from cops.execution.control import (
    REQUEST_SCHEMA,
    RESPONSE_SCHEMA,
    ApprovalAuthority,
    ApprovalControlClient,
    ApprovalControlError,
    _ApprovalControlTransportError,
)
from cops.execution.store import ApprovalStoreConflictError
from tests.auth_testkit import (
    TestExecutionSandbox,
    make_test_approval_authority,
    make_test_authorization_context,
    worker_inventory_for_plan,
)


def _rebuild_plan(plan: ActionPlan, **changes) -> ActionPlan:
    document = plan.to_dict()
    document.pop("schema_version")
    document.pop("plan_digest")
    document.update(changes)
    return ActionPlan.create(**document)


@pytest.fixture
def authority_context(tmp_path, monkeypatch):
    # This deliberately simulates authority readiness, not Linux peer isolation.
    monkeypatch.setattr("cops.execution.control.sys_platform_linux", lambda: True)
    fixture = Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json"
    original = ActionPlan.from_dict(json.loads(fixture.read_text(encoding="utf-8")))
    plan = _rebuild_plan(
        original,
        operations=[
            {
                "step_id": "step-qualified",
                "tool": "qualification-tool",
                "tool_version": "1.0.0",
                "action": "run",
                "arguments": {},
                "timeout_seconds": 10,
                "idempotent": False,
            }
        ],
        credential_references=[],
    )
    return make_test_approval_authority(tmp_path, plan)


def _request(authorization, plan, **changes):
    request = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": str(uuid.uuid4()),
        "operation": "consume",
        "authorization_id": authorization.authorization_id,
        "worker_identity": "worker-01",
        "action_plan": plan.to_dict(),
    }
    request.update(changes)
    return request


def _consume(authority, request):
    return authority.consume_document(
        request,
        peer_pid=authority.worker_pid,
        peer_uid=authority.worker_uid,
        peer_gid=authority.worker_gid,
    )


def _exchange_response(authority, request):
    try:
        return _consume(authority, request)
    except (ApprovalControlError, ApprovalStoreConflictError):
        # Match the production server's fail-closed wire response.
        return {
            "schema_version": RESPONSE_SCHEMA,
            "request_id": request["request_id"],
            "ok": False,
            "error": "approval authority rejected the request",
        }


def _consumption_count(authority):
    with sqlite3.connect(authority.store.db_path) as connection:
        return connection.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0]


@pytest.mark.parametrize("binding", ["engagement", "worker", "plan-id", "operation-digest"])
def test_context_mismatch_never_consumes_approval(authority_context, binding):
    authority, authorization, plan = authority_context
    request = _request(authorization, plan)
    if binding == "worker":
        request["worker_identity"] = "worker-other"
    else:
        changes = {
            "engagement": {"engagement_id": "eng-other"},
            "plan-id": {"plan_id": "plan-other"},
            "operation-digest": {"operations": [{**plan.to_dict()["operations"][0], "arguments": {"role": "other"}}]},
        }
        altered = _rebuild_plan(plan, **changes[binding])
        assert altered.plan_digest != plan.plan_digest
        request["action_plan"] = altered.to_dict()

    with pytest.raises(ApprovalControlError):
        _consume(authority, request)

    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"
    assert _consumption_count(authority) == 0


@pytest.mark.parametrize("condition", ["expired", "not-yet-valid", "revoked-key"])
def test_invalid_authorization_lifecycle_never_consumes(authority_context, condition):
    authority, authorization, plan = authority_context
    signer, trust_store, engagement = make_test_authorization_context(plan)
    if condition == "revoked-key":
        revoked = TrustedAuthorizationKey(signer.key_id, signer.operator, b"", status="revoked")
        authority = replace(authority, trust_store=AuthorizationTrustStore([revoked]))
    else:
        now = datetime.now(UTC)
        issued_at = now + timedelta(hours=1) if condition == "not-yet-valid" else now - timedelta(hours=2)
        authorization = create_execution_authorization(
            plan,
            signer=signer,
            engagement=engagement,
            worker_identity="worker-01",
            issued_at=issued_at.isoformat().replace("+00:00", "Z"),
            authorized_until_utc=(issued_at + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        )
        authority.store.store_authorization(authorization)
        authority = replace(authority, trust_store=trust_store)

    with pytest.raises(ApprovalControlError):
        _consume(authority, _request(authorization, plan))

    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"
    assert _consumption_count(authority) == 0


def _consume_in_fresh_process(connection, database_path, plan_document, request, authority_bindings):
    import cops.execution.control as control

    # Child readiness is also explicitly simulated. No Linux account claim.
    control.sys_platform_linux = lambda: True
    plan = ActionPlan.from_dict(plan_document)
    _, trust_store, engagement = make_test_authorization_context(plan)
    authority = ApprovalAuthority(
        store=ApprovalStore(database_path),
        trust_store=trust_store,
        engagement=engagement,
        **authority_bindings,
    )
    try:
        connection.send(_consume(authority, request))
    finally:
        connection.close()


def test_restarted_authority_preserves_exact_retry_and_denies_new_request(authority_context):
    authority, authorization, plan = authority_context
    request = _request(authorization, plan)
    response = _consume(authority, request)

    # Spawn imports a fresh interpreter; no receipt cache or connection survives.
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(
        target=_consume_in_fresh_process,
        args=(
            send,
            authority.store.db_path,
            plan.to_dict(),
            request,
            {
                name: getattr(authority, name)
                for name in ("worker_identity", "worker_uid", "worker_gid", "worker_pid", "authority_uid")
            },
        ),
    )
    try:
        process.start()
        send.close()
        assert receive.poll(10), "restarted authority did not return its durable receipt"
        assert receive.recv() == response
        process.join(10)
        assert process.exitcode == 0
    finally:
        receive.close()
        send.close()
        if process.is_alive():
            process.kill()
            process.join(5)

    restarted = replace(authority, store=ApprovalStore(authority.store.db_path))
    assert _consume(restarted, json.loads(json.dumps(request))) == response
    with pytest.raises(ApprovalControlError):
        _consume(restarted, _request(authorization, plan))
    assert restarted.store.get_authorization(authorization.authorization_id).status == "consumed"
    assert _consumption_count(restarted) == 1


def test_concurrent_same_request_returns_one_durable_receipt(authority_context):
    authority, authorization, plan = authority_context
    request = _request(authorization, plan)
    barrier = threading.Barrier(2, timeout=10)

    def consume():
        barrier.wait()
        return _consume(authority, json.loads(json.dumps(request)))

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(consume) for _ in range(2)]
        responses = [future.result(timeout=15) for future in futures]

    assert responses[0] == responses[1]
    assert _consumption_count(authority) == 1


def _worker(tmp_path, authority, plan, monkeypatch, suffix):
    registry = ToolAdapterRegistry(definitions_path=tmp_path / "no-definitions")
    registry.register_adapter(
        ToolAdapter(
            tool="qualification-tool",
            version="1.0.0",
            binary="qualification-tool",
            provenance={
                "source": "https://example.invalid/qualification",
                "license": "MIT",
                "pinned_revision": "1.0.0",
            },
            supported_environments=["linux", "darwin"],
            actions={
                "run": ToolActionDefinition(
                    action="run", description="Count a test dispatch", base_args=[], parameters={}
                )
            },
            executable_verification=ExecutableVerification(
                sha256="0" * 64,
                version_args=("--version",),
                version_pattern=r"(?P<version>[0-9.]+)",
            ),
        )
    )
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr("cops.execution.worker.verify_executable_launch_support", lambda: None)
    monkeypatch.setattr("cops.execution.worker.prepare_executable", lambda *args, **kwargs: prepared)
    journal = tmp_path / f"journal-{suffix}"
    journal.mkdir(mode=0o700)
    client = ApprovalControlClient(
        socket_path=tmp_path / "simulated.sock", expected_authority_uid=authority.authority_uid
    )
    sandbox = TestExecutionSandbox()
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="worker-01"),
        client,
        sandbox,
        adapter_registry=registry,
        cleanup_journal_path=journal / "cleanup.sqlite3",
    )
    return worker, sandbox


def test_competing_worker_requests_dispatch_exactly_once(authority_context, tmp_path, monkeypatch):
    authority, authorization, plan = authority_context
    barrier = threading.Barrier(2, timeout=10)
    request_ids = []
    monkeypatch.setattr(ApprovalControlClient, "assert_ready", lambda self, worker_identity: None)

    def exchange(self, request):
        request_ids.append(request["request_id"])
        barrier.wait()
        return _exchange_response(authority, request)

    monkeypatch.setattr(ApprovalControlClient, "_exchange", exchange)
    workers = [_worker(tmp_path, authority, plan, monkeypatch, str(index)) for index in range(2)]
    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(worker.execute_plan, plan, authorization=authorization.authorization_id)
            for worker, _ in workers
        ]
        for future in futures:
            try:
                outcomes.append(future.result(timeout=15))
            except ApprovalControlError as error:
                outcomes.append(error)

    assert len(set(request_ids)) == 2
    assert sum(isinstance(outcome, ApprovalControlError) for outcome in outcomes) == 1
    assert [outcome.status for outcome in outcomes if not isinstance(outcome, ApprovalControlError)] == ["success"]
    assert sum(len(sandbox.run_calls) for _, sandbox in workers) == 1
    assert _consumption_count(authority) == 1


def test_lost_response_then_reopened_authority_dispatches_exactly_once(authority_context, tmp_path, monkeypatch):
    authority, authorization, plan = authority_context
    request_ids = []
    monkeypatch.setattr(ApprovalControlClient, "assert_ready", lambda self, worker_identity: None)

    def exchange(self, request):
        request_ids.append(request["request_id"])
        reopened = replace(authority, store=ApprovalStore(authority.store.db_path))
        response = _exchange_response(reopened, request)
        if len(request_ids) == 1:
            raise _ApprovalControlTransportError("injected response loss after durable commit")
        return response

    monkeypatch.setattr(ApprovalControlClient, "_exchange", exchange)
    worker, sandbox = _worker(tmp_path, authority, plan, monkeypatch, "response-loss")
    result = worker.execute_plan(plan, authorization=authorization.authorization_id)

    assert result.status == "success"
    assert len(request_ids) == 2
    assert request_ids[0] == request_ids[1]
    assert len(sandbox.run_calls) == 1
    assert _consumption_count(authority) == 1
    replay_worker, replay_sandbox = _worker(tmp_path, authority, plan, monkeypatch, "replay")
    with pytest.raises(ApprovalControlError, match="rejected"):
        replay_worker.execute_plan(plan, authorization=authorization.authorization_id)
    assert len(sandbox.run_calls) == 1
    assert len(replay_sandbox.run_calls) == 0
    assert _consumption_count(authority) == 1
