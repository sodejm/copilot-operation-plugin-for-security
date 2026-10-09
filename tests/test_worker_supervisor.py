"""Boundary tests for the persistent worker behind the SSH relay."""

from __future__ import annotations

import json
import os
import socket
import struct
import time
from pathlib import Path

import pytest

from cops import worker_supervisor as supervisor


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
