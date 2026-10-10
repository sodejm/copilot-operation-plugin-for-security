"""Security boundary tests for the separate approval authority process."""

from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest
from cops.execution.authorization import create_execution_authorization
from cops.execution.control import (
    REQUEST_SCHEMA,
    RESPONSE_SCHEMA,
    ApprovalAuthority,
    ApprovalAuthorityServer,
    ApprovalControlClient,
    ApprovalControlError,
    _ApprovalControlTransportError,
)
from cops.execution.store import (
    ApprovalStore,
    ApprovalStoreAccessError,
    ApprovalStoreConflictError,
)
from tests.auth_testkit import make_test_authorization_context

WORKER_IDENTITY = "worker-01"


def _plan() -> ActionPlan:
    fixture = Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json"
    return ActionPlan.from_dict(json.loads(fixture.read_text(encoding="utf-8")))


def _different_plan(plan: ActionPlan) -> ActionPlan:
    snapshot = plan.approved_snapshot()
    return ActionPlan.create(
        plan_id="plan-authority-mismatch",
        engagement_id=plan.engagement_id,
        scenario_id=plan.scenario_id,
        target=plan.target,
        specialist_id=plan.specialist_id,
        operations=snapshot["operations"],
        limits=snapshot["limits"],
        credential_references=snapshot["credential_references"],
        created_at=plan.created_at,
        platform_prerequisites=snapshot["platform_prerequisites"],
        batch=snapshot["batch"],
    )


@pytest.fixture
def authority_context(tmp_path, monkeypatch):
    monkeypatch.setattr("cops.execution.control.sys_platform_linux", lambda: True)
    plan = _plan()
    signer, trust_store, engagement = make_test_authorization_context(plan)
    authorization = create_execution_authorization(
        plan,
        signer=signer,
        engagement=engagement,
        worker_identity=WORKER_IDENTITY,
        valid_hours=1,
    )
    store = ApprovalStore(tmp_path / "authority-store" / "approvals.sqlite3")
    store.store_authorization(authorization)
    authority_uid = os.geteuid()
    authority = ApprovalAuthority(
        store=store,
        trust_store=trust_store,
        engagement=engagement,
        worker_identity=WORKER_IDENTITY,
        worker_uid=authority_uid + 1,
        worker_gid=os.getegid(),
        worker_pid=4242,
        authority_uid=authority_uid,
    )
    return authority, authorization, plan


def _request(authorization_id: str, plan: ActionPlan, **replacements):
    document = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": str(uuid.uuid4()),
        "operation": "consume",
        "authorization_id": authorization_id,
        "worker_identity": WORKER_IDENTITY,
        "action_plan": plan.to_dict(),
    }
    document.update(replacements)
    return document


def _consume(authority: ApprovalAuthority, document):
    return authority.consume_document(
        document,
        peer_pid=authority.worker_pid,
        peer_uid=authority.worker_uid,
        peer_gid=authority.worker_gid,
    )


def test_authority_returns_exact_consumed_authorization_bindings(authority_context):
    authority, authorization, plan = authority_context

    response = _consume(authority, _request(authorization.authorization_id, plan))

    assert set(response) == {
        "schema_version",
        "request_id",
        "ok",
        "authorization_id",
        "authorization_digest",
        "action_plan_id",
        "plan_digest",
        "engagement_id",
        "worker_identity",
        "target",
    }
    assert response["schema_version"] == RESPONSE_SCHEMA
    assert response["ok"] is True
    assert response["authorization_id"] == authorization.authorization_id
    assert response["action_plan_id"] == plan.plan_id
    assert response["plan_digest"] == plan.plan_digest
    assert response["engagement_id"] == plan.engagement_id
    assert response["worker_identity"] == WORKER_IDENTITY
    assert response["target"] == plan.target
    assert "signature_digest" not in response
    assert authority.store.get_authorization(authorization.authorization_id).status == "consumed"


def test_authority_returns_the_durable_receipt_for_an_exact_retry(authority_context):
    authority, authorization, plan = authority_context
    request = _request(authorization.authorization_id, plan)

    first = _consume(authority, request)
    retried = _consume(authority, request)

    assert retried == first
    with sqlite3.connect(authority.store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM approval_consumptions").fetchall()
    assert len(rows) == 1
    assert dict(rows[0]) == {
        "request_id": request["request_id"],
        "request_digest": digest(request),
        "authorization_id": authorization.authorization_id,
        "authorization_digest": first["authorization_digest"],
        "action_plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "engagement_id": plan.engagement_id,
        "worker_identity": WORKER_IDENTITY,
        "target": plan.target,
        "created_at": authority.store.get_authorization(authorization.authorization_id).consumed_at,
    }


def test_authority_rejects_altered_reuse_of_a_consumed_request_id(authority_context):
    authority, authorization, plan = authority_context
    request = _request(authorization.authorization_id, plan)
    _consume(authority, request)
    altered = {
        **request,
        "action_plan": _different_plan(plan).to_dict(),
    }

    with pytest.raises(ApprovalStoreConflictError, match="already used for a different request"):
        _consume(authority, altered)


def test_authority_checks_store_postconditions_before_consuming(authority_context, monkeypatch):
    authority, authorization, plan = authority_context
    original_assertion = authority.store.assert_protected_owner
    assertion_calls = 0

    def fail_precommit_postcondition(authority_uid: int) -> None:
        nonlocal assertion_calls
        assertion_calls += 1
        if assertion_calls == 2:
            raise ApprovalStoreAccessError("injected ownership change")
        original_assertion(authority_uid)

    monkeypatch.setattr(
        authority.store,
        "assert_protected_owner",
        fail_precommit_postcondition,
    )

    with pytest.raises(ApprovalStoreAccessError, match="injected ownership change"):
        _consume(authority, _request(authorization.authorization_id, plan))

    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"
    with sqlite3.connect(authority.store.db_path) as conn:
        receipt_count = conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0]
    assert receipt_count == 0


def test_client_retries_the_same_request_after_response_loss(authority_context, monkeypatch, tmp_path):
    authority, authorization, plan = authority_context
    request_ids: list[str] = []

    monkeypatch.setattr(
        ApprovalControlClient,
        "assert_ready",
        lambda self, worker_identity: None,
    )

    def lose_first_response(self, request):
        del self
        response = _consume(authority, request)
        request_ids.append(request["request_id"])
        if len(request_ids) == 1:
            raise _ApprovalControlTransportError("injected response loss after commit")
        return response

    monkeypatch.setattr(ApprovalControlClient, "_exchange", lose_first_response)
    client = ApprovalControlClient(
        socket_path=tmp_path / "unused.sock",
        expected_authority_uid=authority.authority_uid,
    )

    receipt = client.consume_authorization(
        authorization.authorization_id,
        plan,
        WORKER_IDENTITY,
    )

    assert len(request_ids) == 2
    assert request_ids[0] == request_ids[1]
    assert receipt.authorization_id == authorization.authorization_id
    assert receipt.plan_digest == plan.plan_digest
    client.validate_receipt_provenance(receipt)
    with sqlite3.connect(authority.store.db_path) as conn:
        receipt_count = conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0]
    assert receipt_count == 1


@pytest.mark.parametrize(
    ("request_changes", "peer_changes", "message"),
    [
        ({"operation": "create"}, {}, "unsupported approval control request"),
        ({"worker_identity": "worker-02"}, {}, "worker identity mismatch"),
        ({"request_id": "not-a-uuid"}, {}, "request_id must be a UUID"),
        ({}, {"peer_pid": 9001}, "peer PID"),
        ({}, {"peer_uid": 9002}, "peer UID"),
        ({}, {"peer_gid": 9003}, "peer GID"),
    ],
)
def test_authority_rejects_creation_identity_and_peer_spoofing_without_consuming(
    authority_context, request_changes, peer_changes, message
):
    authority, authorization, plan = authority_context
    peers = {
        "peer_pid": authority.worker_pid,
        "peer_uid": authority.worker_uid,
        "peer_gid": authority.worker_gid,
    }
    peers.update(peer_changes)

    with pytest.raises(ApprovalControlError, match=message):
        authority.consume_document(
            _request(authorization.authorization_id, plan, **request_changes),
            **peers,
        )

    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"


def test_authority_rejects_a_different_valid_plan_before_consumption(authority_context):
    authority, authorization, plan = authority_context

    with pytest.raises(ApprovalControlError, match="requested plan and worker"):
        _consume(
            authority,
            _request(authorization.authorization_id, _different_plan(plan)),
        )

    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"


@pytest.mark.parametrize("trailer", [b"extra", b"\n{}\n"])
def test_authority_rejects_bytes_after_request_newline_before_consumption(authority_context, monkeypatch, trailer):
    authority, authorization, plan = authority_context
    monkeypatch.setattr(
        "cops.execution.control._peer_credentials",
        lambda connection: (authority.worker_pid, authority.worker_uid, authority.worker_gid),
    )
    server_connection, peer_connection = socket.socketpair()
    request = _request(authorization.authorization_id, plan)
    encoded = json.dumps(request).encode("utf-8") + b"\n" + trailer

    def serve() -> None:
        with server_connection:
            authority.serve_connection(server_connection)

    server = threading.Thread(target=serve)
    server.start()
    try:
        peer_connection.settimeout(1)
        peer_connection.sendall(encoded)
        peer_connection.shutdown(socket.SHUT_WR)
        response = json.loads(peer_connection.makefile("rb").readline())
    finally:
        peer_connection.close()
        server.join(timeout=1)

    assert not server.is_alive()
    assert response["ok"] is False
    assert authority.store.get_authorization(authorization.authorization_id).status == "approved"


def test_authority_waits_for_request_eof_before_consumption(authority_context, monkeypatch):
    authority, authorization, plan = authority_context
    monkeypatch.setattr(
        "cops.execution.control._peer_credentials",
        lambda connection: (authority.worker_pid, authority.worker_uid, authority.worker_gid),
    )
    server_connection, peer_connection = socket.socketpair()
    request = _request(authorization.authorization_id, plan)

    def serve() -> None:
        with server_connection:
            authority.serve_connection(server_connection)

    server = threading.Thread(target=serve)
    server.start()
    try:
        peer_connection.sendall(json.dumps(request).encode("utf-8") + b"\n")
        peer_connection.settimeout(0.05)
        with pytest.raises(socket.timeout):
            peer_connection.recv(1)
        assert authority.store.get_authorization(authorization.authorization_id).status == "approved"
        peer_connection.shutdown(socket.SHUT_WR)
        peer_connection.settimeout(1)
        response = json.loads(peer_connection.makefile("rb").readline())
    finally:
        peer_connection.close()
        server.join(timeout=1)

    assert not server.is_alive()
    assert response["ok"] is True
    assert authority.store.get_authorization(authorization.authorization_id).status == "consumed"


def test_client_cannot_override_its_actual_uid_or_gid(tmp_path, monkeypatch):
    monkeypatch.setattr("cops.execution.control.sys_platform_linux", lambda: True)
    monkeypatch.setattr(os, "geteuid", lambda: 2001)
    monkeypatch.setattr(os, "getegid", lambda: 2002)
    client = ApprovalControlClient(
        socket_path=tmp_path / "authority.sock",
        expected_authority_uid=1001,
        worker_uid=2999,
        worker_gid=2002,
    )

    with pytest.raises(ApprovalControlError, match="do not match the running process"):
        client.assert_ready(WORKER_IDENTITY)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the production authority socket boundary is Linux-only",
)
def test_authority_listener_requires_protected_startup_and_leaves_no_socket(authority_context):
    authority, _, _ = authority_context
    control_dir = Path(tempfile.mkdtemp(prefix="cops-control-", dir="/tmp"))
    os.chown(control_dir, -1, authority.worker_gid)
    control_dir.chmod(0o2710)
    try:
        server = ApprovalAuthorityServer(control_dir / "authority.sock", authority)

        with server.listener() as listener:
            socket_stat = os.lstat(server.socket_path)
            assert stat.S_ISSOCK(socket_stat.st_mode)
            assert stat.S_IMODE(socket_stat.st_mode) == 0o660
            assert listener.get_inheritable() is False

        assert not os.path.lexists(server.socket_path)
    finally:
        shutil.rmtree(control_dir)


def test_authority_listener_rejects_insecure_control_directory(authority_context, tmp_path):
    authority, _, _ = authority_context
    control_dir = tmp_path / "control"
    control_dir.mkdir(mode=0o700)
    server = ApprovalAuthorityServer(control_dir / "authority.sock", authority)

    with pytest.raises(ApprovalControlError, match="mode 2710"):
        with server.listener():
            pass


def test_authority_server_deadlines_a_peer_that_never_sends_a_document(tmp_path):
    class BlockingAuthority:
        timed_out = False

        def serve_connection(self, connection):
            try:
                connection.recv(1)
            except TimeoutError:
                self.timed_out = True
                raise

    authority = BlockingAuthority()
    server = ApprovalAuthorityServer(
        tmp_path / "unused.sock",
        authority,  # type: ignore[arg-type]
        connection_timeout_seconds=0.01,
    )
    server_connection, peer_connection = socket.socketpair()
    started = time.monotonic()
    try:
        with pytest.raises(socket.timeout):
            server._serve_accepted_connection(server_connection)
    finally:
        peer_connection.close()

    assert authority.timed_out is True
    assert time.monotonic() - started < 0.5


def test_authority_server_uses_total_deadline_against_slow_drip_peer(tmp_path):
    class DrainingAuthority:
        received = 0

        def serve_connection(self, connection):
            while True:
                self.received += len(connection.recv(1))

    authority = DrainingAuthority()
    server = ApprovalAuthorityServer(
        tmp_path / "unused.sock",
        authority,  # type: ignore[arg-type]
        connection_timeout_seconds=0.03,
    )
    server_connection, peer_connection = socket.socketpair()
    stop = threading.Event()

    def drip() -> None:
        try:
            while not stop.wait(0.005):
                peer_connection.sendall(b"x")
        except OSError:
            pass

    sender = threading.Thread(target=drip)
    sender.start()
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            server._serve_accepted_connection(server_connection)
    finally:
        stop.set()
        peer_connection.close()
        sender.join(timeout=1)

    assert authority.received > 1
    assert time.monotonic() - started < 0.5


def test_store_rejects_preexisting_insecure_database_without_repairing_it(tmp_path):
    store_dir = tmp_path / "authority-store"
    store_dir.mkdir(mode=0o700)
    database = store_dir / "approvals.sqlite3"
    database.write_bytes(b"")
    database.chmod(0o644)

    with pytest.raises(ApprovalStoreAccessError, match="insecure permissions"):
        ApprovalStore(database)

    assert stat.S_IMODE(os.lstat(database).st_mode) == 0o644


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_store_rejects_insecure_sqlite_sidecars(tmp_path, suffix, monkeypatch):
    store = ApprovalStore(tmp_path / "authority-store" / "approvals.sqlite3")
    sidecar = Path(f"{store.db_path}{suffix}")
    real_lexists = os.path.lexists
    real_lstat = os.lstat
    database_stat = real_lstat(store.db_path)
    insecure_values = list(database_stat)
    insecure_values[stat.ST_MODE] = stat.S_IFREG | 0o644
    insecure_stat = os.stat_result(insecure_values)

    monkeypatch.setattr(
        os.path,
        "lexists",
        lambda path: True if Path(path) == sidecar else real_lexists(path),
    )
    monkeypatch.setattr(
        os,
        "lstat",
        lambda path: insecure_stat if Path(path) == sidecar else real_lstat(path),
    )

    with pytest.raises(ApprovalStoreAccessError, match="sidecar permissions"):
        store.assert_protected_owner(os.geteuid())
