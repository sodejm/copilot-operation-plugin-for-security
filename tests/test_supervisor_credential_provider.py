from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

import cops.execution.credential_provider as provider_module
import cops.worker_supervisor as supervisor
from cops.execution.credential_provider import (
    PROTOCOL,
    CredentialProviderTransportError,
    UnixSocketCredentialProvider,
)


class _FakeSocket:
    def __init__(self, *, peer_uid: int, peer_gid: int, response: bytes) -> None:
        self.peer_uid = peer_uid
        self.peer_gid = peer_gid
        self.response = response
        self.sent = b""
        self.timeouts: list[float] = []

    def __enter__(self) -> _FakeSocket:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def connect(self, path: str) -> None:
        assert path == "/run/cops/credential-provider.sock"

    def getsockopt(self, level: int, option: int, size: int) -> bytes:
        assert (level, option, size) == (
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        return struct.pack("3i", 4321, self.peer_uid, self.peer_gid)

    def sendall(self, request: bytes) -> None:
        self.sent += request

    def shutdown(self, how: int) -> None:
        assert how == socket.SHUT_WR

    def recv(self, size: int) -> bytes:
        response, self.response = self.response[:size], self.response[size:]
        return response


@dataclass(frozen=True)
class _OperationBoundGrant:
    reference: str
    environment_variable: str
    plan_id: str
    plan_digest: str
    engagement_id: str
    worker_identity: str
    target: str
    operation_index: int
    operation_digest: str
    step_id: str
    tool: str
    tool_version: str
    action: str


def _config(manifest_path: Path) -> supervisor.WorkerSupervisorConfig:
    return supervisor.WorkerSupervisorConfig(
        expected_host="worker.example",
        worker_identity="worker-1",
        socket_path=Path("/run/cops/worker.sock"),
        relay_uid=1002,
        relay_gid=1002,
        supervisor_uid=1001,
        supervisor_gid=1001,
        authority_uid=1003,
        approval_socket_path=Path("/run/cops/approval.sock"),
        inventory_path=Path("/etc/cops/inventory.json"),
        engagement_path=Path("/etc/cops/engagement.json"),
        attestation_key_id="supervisor-key",
        attestation_key_path=Path("/etc/cops/attestation.key"),
        executable_sha256_pins={},
        credential_manifest_path=manifest_path,
    )


def _manifest() -> dict[str, object]:
    return {
        "schema_version": supervisor.CREDENTIAL_MANIFEST_SCHEMA,
        "provider_socket_path": "/run/cops/credential-provider.sock",
        "provider_uid": 1004,
        "provider_gid": 1004,
        "provider_timeout_seconds": 2.0,
        "grants": [
            {
                "reference": "vault://engagements/eng-1/api-token",
                "environment_variable": "COPS_CREDENTIAL_API_TOKEN",
                "plan_id": "plan-1",
                "plan_digest": "a" * 64,
                "engagement_id": "eng-1",
                "worker_identity": "worker-1",
                "target": "api.example.test",
                "operation_index": 0,
                "operation_digest": "b" * 64,
                "step_id": "step-1",
                "tool": "curl",
                "tool_version": "8.0",
                "action": "read",
            }
        ],
    }


def _write_manifest(path: Path) -> None:
    path.write_text(json.dumps(_manifest()), encoding="utf-8")
    path.chmod(0o600)


def test_provider_uses_pinned_peer_and_sends_only_opaque_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provider_module.socket, "SO_PEERCRED", 17, raising=False)
    secret = "secret-that-must-not-be-sent-in-the-request"
    reference = "vault://engagements/eng-1/api-token"
    response = (
        json.dumps(
            {"protocol": PROTOCOL, "reference": reference, "value": secret},
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    connection = _FakeSocket(peer_uid=1004, peer_gid=1004, response=response)
    provider = UnixSocketCredentialProvider(
        "/run/cops/credential-provider.sock",
        expected_provider_uid=1004,
        expected_provider_gid=1004,
    )
    monkeypatch.setattr(provider, "_validate_socket_path", lambda: None)
    monkeypatch.setattr(provider_module.socket, "socket", lambda *args: connection)

    assert provider.resolve(reference, timeout=1.0) == secret
    assert json.loads(connection.sent) == {"protocol": PROTOCOL, "reference": reference}
    assert secret.encode() not in connection.sent
    assert connection.timeouts and all(timeout > 0 for timeout in connection.timeouts)


def test_provider_rejects_unpinned_peer_before_sending_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provider_module.socket, "SO_PEERCRED", 17, raising=False)
    connection = _FakeSocket(peer_uid=9999, peer_gid=1004, response=b"")
    provider = UnixSocketCredentialProvider(
        "/run/cops/credential-provider.sock",
        expected_provider_uid=1004,
        expected_provider_gid=1004,
    )
    monkeypatch.setattr(provider, "_validate_socket_path", lambda: None)
    monkeypatch.setattr(provider_module.socket, "socket", lambda *args: connection)

    with pytest.raises(CredentialProviderTransportError, match="peer identity mismatch"):
        provider.resolve("vault://engagements/eng-1/api-token", timeout=1.0)

    assert connection.sent == b""


def test_manifest_builds_operation_bound_grant_with_same_approval_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = tmp_path / "credentials.json"
    _write_manifest(manifest_path)
    monkeypatch.setattr(supervisor, "CredentialGrant", _OperationBoundGrant)
    approval_control = object()

    resolver = supervisor._credential_resolver(
        _config(manifest_path),
        engagement_id="eng-1",
        approval_control=approval_control,  # type: ignore[arg-type]
    )

    assert resolver is not None
    assert resolver.approval_control is approval_control
    grant = resolver._grants[0]
    assert grant.operation_index == 0
    assert grant.operation_digest == "b" * 64
    assert "value" not in manifest_path.read_text(encoding="utf-8")


def test_manifest_fails_closed_without_operation_bound_grant_model(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "credentials.json"
    _write_manifest(manifest_path)

    with pytest.raises(supervisor.WorkerSupervisorError, match="exact operation binding"):
        supervisor._credential_resolver(
            _config(manifest_path),
            engagement_id="eng-1",
            approval_control=object(),  # type: ignore[arg-type]
        )
