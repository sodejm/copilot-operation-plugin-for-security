"""Boundary tests for the persistent worker behind the SSH relay."""

from __future__ import annotations

import json
import os
import socket
import struct
import time
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cops import worker_supervisor as supervisor
from cops.contracts import ActionPlan
from cops.evidence.canonical import digest
from cops.execution import ApprovalStore, IsolatedWorker, WorkerExecutionError, WorkerIsolationError
from cops.execution.offline_research import OfflineResearchError, validate_offline_request
from tests.auth_testkit import TestApprovalControl, authorize_test_plan, worker_inventory_for_plan
from tests.test_offline_research import WORKER_ID, _plan, _profile


class _Connection:
    def __init__(self, chunks: list[bytes], *, uid: int, gid: int) -> None:
        self.chunks = chunks
        self.uid = uid
        self.gid = gid
        self.sent = b""
        self.timeouts: list[float] = []

    def getsockopt(self, _level: int, _option: int, _length: int) -> bytes:
        return struct.pack("3i", 1234, self.uid, self.gid)

    def recv(self, count: int) -> bytes:
        chunk = self.chunks.pop(0) if self.chunks else b""
        assert len(chunk) <= count
        return chunk

    def settimeout(self, seconds: float) -> None:
        self.timeouts.append(seconds)

    def sendall(self, data: bytes) -> None:
        self.sent += data


class _Receiver:
    def __init__(self) -> None:
        self.requests: list[bytes] = []

    def serve_one(self, input_stream, output_stream) -> None:
        self.requests.append(input_stream.read())
        output_stream.write(b'{"ok":true}\n')


class _Attestor:
    def __init__(self) -> None:
        self.exchanges: list[tuple[bytes, bytes]] = []

    def attest(self, request: bytes, response: bytes) -> bytes:
        self.exchanges.append((request, response))
        return b'{"signed":true}\n'


def _config(tmp_path: Path) -> supervisor.WorkerSupervisorConfig:
    attestation_key_path = tmp_path / "attestation.key"
    attestation_key_path.write_text("22" * 32, encoding="ascii")
    attestation_key_path.chmod(0o600)
    return supervisor.WorkerSupervisorConfig(
        expected_host="worker.example.test",
        worker_identity="worker-01",
        socket_path=tmp_path / "relay.sock",
        relay_uid=1002,
        relay_gid=1002,
        supervisor_uid=1001,
        supervisor_gid=1001,
        authority_uid=1003,
        approval_socket_path=tmp_path / "approval.sock",
        cleanup_journal_path=tmp_path / "cleanup.sqlite3",
        inventory_path=tmp_path / "inventory.json",
        engagement_path=tmp_path / "engagement.json",
        executable_sha256_pins={},
        attestation_key_id="supervisor-key-01",
        attestation_key_path=attestation_key_path,
    )


def test_supervisor_accepts_one_complete_request_from_pinned_relay(tmp_path, monkeypatch):
    monkeypatch.setattr(supervisor.sys, "platform", "linux")
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    config = _config(tmp_path)
    request = b'{"protocol":"cops.remote-worker/v1"}\n'
    connection = _Connection([request[:10], request[10:], b""], uid=1002, gid=1002)
    receiver = _Receiver()
    attestor = _Attestor()

    supervisor.serve_connection(connection, config, receiver, attestor)

    assert receiver.requests == [request]
    assert connection.sent == b'{"signed":true}\n'
    assert attestor.exchanges == [(request, b'{"ok":true}\n')]
    assert connection.timeouts and all(value > 0 for value in connection.timeouts)


def test_supervisor_response_deadline_starts_after_worker_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(supervisor.sys, "platform", "linux")
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    current_time = [0.0]
    monkeypatch.setattr(supervisor.time, "monotonic", lambda: current_time[0])
    config = _config(tmp_path)
    connection = _Connection([b"{}\n", b""], uid=1002, gid=1002)

    class SlowReceiver(_Receiver):
        def serve_one(self, input_stream, output_stream) -> None:
            super().serve_one(input_stream, output_stream)
            current_time[0] = 60.0

    attestor = _Attestor()
    supervisor.serve_connection(connection, config, SlowReceiver(), attestor)

    assert connection.sent == b'{"signed":true}\n'
    assert attestor.exchanges == [(b"{}\n", b'{"ok":true}\n')]
    assert connection.timeouts[-1] == 30.0


@pytest.mark.parametrize(
    ("chunks", "error"),
    [
        ([b'{"a":1}', b""], "complete newline-delimited"),
        ([b'{"a":1}\n{}\n', b""], "complete newline-delimited"),
        ([b"x" * supervisor.MAX_REQUEST_BYTES, b"x"], "byte limit"),
    ],
)
def test_supervisor_rejects_partial_extra_and_oversize_requests(tmp_path, monkeypatch, chunks, error):
    monkeypatch.setattr(supervisor.sys, "platform", "linux")
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    config = _config(tmp_path)
    connection = _Connection(chunks, uid=1002, gid=1002)
    receiver = _Receiver()
    attestor = _Attestor()

    with pytest.raises(supervisor.WorkerSupervisorError, match=error):
        supervisor.serve_connection(connection, config, receiver, attestor)

    assert receiver.requests == []
    assert connection.sent == b""


def test_supervisor_rejects_wrong_peer_before_read_or_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(supervisor.sys, "platform", "linux")
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    config = _config(tmp_path)
    connection = _Connection([b"{}\n", b""], uid=1004, gid=1002)
    receiver = _Receiver()
    attestor = _Attestor()

    with pytest.raises(supervisor.WorkerSupervisorError, match="relay peer identity mismatch"):
        supervisor.serve_connection(connection, config, receiver, attestor)

    assert connection.chunks == [b"{}\n", b""]
    assert receiver.requests == []


def test_supervisor_rejects_expired_request_deadline(tmp_path):
    connection = _Connection([b"{}\n"], uid=1002, gid=1002)
    with pytest.raises(supervisor.WorkerSupervisorError, match="deadline exceeded"):
        supervisor._read_complete_request(connection, time.monotonic() - 1)
    assert connection.chunks == [b"{}\n"]


def test_supervisor_inputs_are_owner_only_and_not_symlinks(tmp_path):
    source = tmp_path / "config.json"
    source.write_text(json.dumps({"schema_version": supervisor.CONFIG_SCHEMA}), encoding="utf-8")
    source.chmod(0o600)
    assert supervisor._owner_only_json(source)["schema_version"] == supervisor.CONFIG_SCHEMA

    source.chmod(0o640)
    with pytest.raises(supervisor.WorkerSupervisorError, match="owner-only"):
        supervisor._owner_only_json(source)

    source.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(source)
    with pytest.raises(supervisor.WorkerSupervisorError, match="unavailable"):
        supervisor._owner_only_json(link)


def test_supervisor_config_requires_distinct_accounts(tmp_path):
    config = _config(tmp_path)
    data = {
        "schema_version": supervisor.CONFIG_SCHEMA,
        "expected_host": config.expected_host,
        "worker_identity": config.worker_identity,
        "socket_path": str(config.socket_path),
        "relay_uid": os.geteuid(),
        "relay_gid": config.relay_gid,
        "supervisor_uid": os.geteuid(),
        "supervisor_gid": os.getegid(),
        "authority_uid": config.authority_uid,
        "approval_socket_path": str(config.approval_socket_path),
        "cleanup_journal_path": str(config.cleanup_journal_path),
        "inventory_path": str(config.inventory_path),
        "engagement_path": str(config.engagement_path),
        "executable_sha256_pins": {},
        "attestation_key_id": config.attestation_key_id,
        "attestation_key_path": str(config.attestation_key_path),
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(supervisor.WorkerSupervisorError, match="separate UIDs"):
        supervisor.WorkerSupervisorConfig.from_file(path)


def test_supervisor_config_requires_persistent_absolute_cleanup_journal(tmp_path):
    config = _config(tmp_path)
    data = {
        "schema_version": supervisor.CONFIG_SCHEMA,
        "expected_host": config.expected_host,
        "worker_identity": config.worker_identity,
        "socket_path": str(config.socket_path),
        "relay_uid": os.geteuid() + 1,
        "relay_gid": os.getegid() + 1,
        "supervisor_uid": os.geteuid(),
        "supervisor_gid": os.getegid(),
        "authority_uid": os.geteuid() + 2,
        "approval_socket_path": str(config.approval_socket_path),
        "inventory_path": str(config.inventory_path),
        "engagement_path": str(config.engagement_path),
        "executable_sha256_pins": {},
        "attestation_key_id": config.attestation_key_id,
        "attestation_key_path": str(config.attestation_key_path),
    }
    path = tmp_path / "config.json"

    def load_config() -> supervisor.WorkerSupervisorConfig:
        path.write_text(json.dumps(data), encoding="utf-8")
        path.chmod(0o600)
        return supervisor.WorkerSupervisorConfig.from_file(path)

    with pytest.raises(supervisor.WorkerSupervisorError, match="fields or schema"):
        load_config()
    data["cleanup_journal_path"] = "relative-journal.sqlite3"
    with pytest.raises(supervisor.WorkerSupervisorError, match="cleanup_journal_path must be an absolute path"):
        load_config()
    data["cleanup_journal_path"] = str(config.cleanup_journal_path)
    assert load_config().cleanup_journal_path == config.cleanup_journal_path
    data["schema_version"] = "cops.worker-supervisor-config/v1"
    with pytest.raises(supervisor.WorkerSupervisorError, match="fields or schema"):
        load_config()


@pytest.mark.parametrize("profile", ["standard", "offline-research/v1"])
def test_supervisor_recovers_cleanup_before_creating_receiver(tmp_path, monkeypatch, profile):
    config = replace(_config(tmp_path), execution_profile=profile)
    events = []
    worker_kwargs = {}

    monkeypatch.setattr(supervisor.WorkerCapabilityInventory, "from_file", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        supervisor.Engagement, "from_dict", lambda data: SimpleNamespace(engagement_id="eng-1", scope={})
    )
    monkeypatch.setattr(supervisor, "_owner_only_json", lambda path: {})
    monkeypatch.setattr(supervisor, "ApprovalControlClient", lambda **kwargs: object())
    monkeypatch.setattr(supervisor, "_credential_resolver", lambda *args, **kwargs: None)
    monkeypatch.setattr(supervisor, "LinuxBubblewrapSandbox", lambda **kwargs: object())
    monkeypatch.setattr(supervisor.ScopeDefinition, "from_engagement_scope", lambda *args, **kwargs: object())
    monkeypatch.setattr(supervisor, "ScopeGuard", lambda *args: object())
    monkeypatch.setattr(supervisor, "ToolAdapterRegistry", lambda **kwargs: object())

    class _Worker:
        def __init__(self, *args, **kwargs):
            worker_kwargs.update(kwargs)

        def recover_pending_cleanup(self):
            events.append("recover")
            return ()

    def receiver(**kwargs):
        events.append("receiver")
        return kwargs

    monkeypatch.setattr(supervisor, "IsolatedWorker", _Worker)
    monkeypatch.setattr(supervisor, "SSHRemoteExecutionReceiver", receiver)
    result = supervisor.build_receiver(config)

    assert events == ["recover", "receiver"]
    assert worker_kwargs["cleanup_journal_path"] == config.cleanup_journal_path
    assert worker_kwargs["required_execution_profile"] == (None if profile == "standard" else profile)
    assert result["worker"].__class__ is _Worker


@pytest.mark.parametrize("profile", ["standard", "offline-research/v1"])
def test_supervisor_fails_startup_when_cleanup_recovery_fails(tmp_path, monkeypatch, profile):
    config = replace(_config(tmp_path), execution_profile=profile)
    monkeypatch.setattr(supervisor.WorkerCapabilityInventory, "from_file", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        supervisor.Engagement, "from_dict", lambda data: SimpleNamespace(engagement_id="eng-1", scope={})
    )
    monkeypatch.setattr(supervisor, "_owner_only_json", lambda path: {})
    monkeypatch.setattr(supervisor, "ApprovalControlClient", lambda **kwargs: object())
    monkeypatch.setattr(supervisor, "_credential_resolver", lambda *args, **kwargs: None)
    monkeypatch.setattr(supervisor, "LinuxBubblewrapSandbox", lambda **kwargs: object())
    monkeypatch.setattr(supervisor.ScopeDefinition, "from_engagement_scope", lambda *args, **kwargs: object())
    monkeypatch.setattr(supervisor, "ScopeGuard", lambda *args: object())
    monkeypatch.setattr(supervisor, "ToolAdapterRegistry", lambda **kwargs: object())

    class _Worker:
        def __init__(self, *args, **kwargs):
            pass

        def recover_pending_cleanup(self):
            raise RuntimeError("cleanup journal is invalid")

    monkeypatch.setattr(supervisor, "IsolatedWorker", _Worker)
    monkeypatch.setattr(supervisor, "SSHRemoteExecutionReceiver", lambda **kwargs: pytest.fail("receiver created"))
    with pytest.raises(RuntimeError, match="cleanup journal is invalid"):
        supervisor.build_receiver(config)


def _config_document(config):
    return {
        "schema_version": supervisor.CONFIG_SCHEMA,
        **{key: str(value) if isinstance(value, Path) else value for key, value in asdict(config).items()},
    }


@pytest.mark.parametrize("profile", [None, "standard", "offline-research/v1"])
def test_supervisor_loads_explicit_profile_and_preserves_default(tmp_path, monkeypatch, profile):
    config = _config(tmp_path)
    data = _config_document(config)
    if profile is None:
        data.pop("execution_profile", None)
    else:
        data["execution_profile"] = profile
    monkeypatch.setattr(supervisor, "_owner_only_json", lambda _path: data)
    monkeypatch.setattr(supervisor.os, "geteuid", lambda: config.supervisor_uid)
    monkeypatch.setattr(supervisor.os, "getegid", lambda: config.supervisor_gid)
    loaded = supervisor.WorkerSupervisorConfig.from_file(tmp_path / "config.json")
    assert loaded.execution_profile == (profile or "standard")


@pytest.mark.parametrize("profile", [None, True, [], {}, "", "offline-research", "offline-research/v2"])
def test_supervisor_rejects_unknown_execution_profile(tmp_path, profile):
    with pytest.raises(supervisor.WorkerSupervisorError, match="execution profile"):
        replace(_config(tmp_path), execution_profile=profile)


@pytest.mark.parametrize(
    "options",
    [{"egress_trust_domain": "example.test"}, {"credential_manifest_path": Path("/unread/manifest.json")}],
)
def test_offline_supervisor_rejects_external_capabilities_at_configuration(tmp_path, options):
    with pytest.raises(supervisor.WorkerSupervisorError, match="cannot configure credentials or egress"):
        replace(_config(tmp_path), execution_profile="offline-research/v1", **options)


def _test_receiver(tmp_path, monkeypatch, profile="offline-research/v1", *, plan=None, inventory=None):
    """Real provisioned files/worker with test-only in-process signed approval."""
    if plan is None:
        source = tmp_path.resolve() / "corpus.txt"
        source.write_text("synthetic corpus\n", encoding="utf-8")
        plan = _plan(_profile(source))
        inventory = worker_inventory_for_plan(plan, worker_identity=WORKER_ID)
        offline = _profile(source)
        offline["worker_inventory_sha256"] = digest(inventory.to_dict())
        plan = _plan(offline)
    authorization, trust, engagement = authorize_test_plan(plan, worker_identity=WORKER_ID)
    store = ApprovalStore(tmp_path / "approvals.sqlite3")
    store.store_authorization(authorization)
    control = TestApprovalControl(store, trust, engagement)
    config = replace(
        _config(tmp_path), worker_identity=WORKER_ID, execution_profile=profile,
        supervisor_uid=os.geteuid(), supervisor_gid=os.getegid(),
        executable_sha256_pins=(
            {"cat": plan.offline_research["cat_executable_sha256"]}
            if plan.offline_research is not None and "cat_executable_sha256" in plan.offline_research else {}
        ),
    )
    for path, document in ((config.inventory_path, inventory.to_dict()), (config.engagement_path, engagement.to_dict())):
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)
    monkeypatch.setattr(supervisor, "ApprovalControlClient", lambda **kwargs: control)
    if profile == "offline-research/v1":
        monkeypatch.setattr(
            supervisor, "_credential_resolver", lambda *args, **kwargs: pytest.fail("credential resolver constructed")
        )
        monkeypatch.setattr(
            supervisor.ScopeDefinition, "from_engagement_scope",
            lambda *args, **kwargs: pytest.fail("external scope constructed"),
        )
    return SimpleNamespace(
        receiver=supervisor.build_receiver(config), config=config, plan=plan, inventory=inventory,
        store=store, control=control, authorization=authorization,
    )


@pytest.mark.parametrize("profile", ["standard", "offline-research/v1"])
def test_supervisor_constructs_only_provisioned_profile(tmp_path, monkeypatch, profile):
    context = _test_receiver(tmp_path, monkeypatch, profile)
    receiver, config, plan, inventory = context.receiver, context.config, context.plan, context.inventory
    worker = receiver.worker
    assert worker.expected_engagement_id == plan.engagement_id
    assert worker.cleanup_journal.path == config.cleanup_journal_path
    if profile == "standard":
        assert worker.scope_guard is not None
        assert worker.required_execution_profile is None
    else:
        assert worker.scope_guard is None
        assert worker.credential_resolver is None
        assert worker._egress_identity_verifier is None
        assert worker.required_execution_profile == "offline-research/v1"
        validate_offline_request(
            plan, worker_identity=WORKER_ID, worker_inventory=inventory.to_dict(),
            cat_executable_sha256=None, sandbox=worker.sandbox, workspace_dir=None,
            scope_guard=worker.scope_guard, credential_resolver=worker.credential_resolver,
            egress_identity_verifier=worker._egress_identity_verifier,
        )
        stripped = plan.approved_snapshot()
        stripped.pop("offline_research")
        stripped.pop("schema_version")
        stripped = ActionPlan.create(**stripped)
        with pytest.raises(WorkerExecutionError, match="requires offline-research/v1"):
            worker.execute_plan_with_receipt(stripped, authorization_id=context.authorization.authorization_id)
        assert context.control.consume_calls == []
        assert context.store.get_authorization(context.authorization.authorization_id).status == "approved"


@pytest.mark.parametrize("options", [{"target": "https://example.invalid"}, {"egress": True}, {"credentials": ["ref"]}])
def test_offline_supervisor_rejects_external_plan_before_consumption(tmp_path, monkeypatch, options):
    context = _test_receiver(tmp_path, monkeypatch)
    plan = _plan(context.plan.approved_snapshot()["offline_research"], **options)
    with pytest.raises((OfflineResearchError, WorkerIsolationError)):
        context.receiver.worker.execute_plan_with_receipt(plan, authorization_id=context.authorization.authorization_id)
    assert context.control.consume_calls == []
    assert context.store.get_authorization(context.authorization.authorization_id).status == "approved"


@pytest.mark.parametrize(
    "options,error",
    [
        ({"required_execution_profile": "unknown"}, "required execution profile is invalid"),
        ({"required_execution_profile": True}, "required execution profile is invalid"),
        ({"scope_guard": object()}, "cannot configure scope, credentials or egress"),
        ({"credential_resolver": object()}, "cannot configure scope, credentials or egress"),
        ({"egress_trust_domain": "example.test"}, "cannot configure scope, credentials or egress"),
    ],
)
def test_direct_offline_worker_cannot_bypass_profile_configuration(tmp_path, monkeypatch, options, error):
    context = _test_receiver(tmp_path, monkeypatch)
    parameters = {"required_execution_profile": "offline-research/v1", **options}
    with pytest.raises(WorkerIsolationError, match=error):
        IsolatedWorker(
            context.inventory, context.control, context.receiver.worker.sandbox,
            cleanup_journal_path=context.config.cleanup_journal_path, **parameters,
        )
    assert context.control.consume_calls == []
