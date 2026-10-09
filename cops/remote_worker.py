"""Remote execution receiver for a persistent, authority-connected worker."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from cops.contracts.models import ActionPlan, RunResult
from cops.execution.control import ApprovalConsumptionReceipt
from cops.execution.filesystem import SecureDirectoryError, open_directory_no_symlinks
from cops.execution.ssh_execution import (
    SSH_EXECUTION_REQUEST_SCHEMA,
    RemoteAuthorizedRun,
    SSHExecutionError,
    _validate_execution_limits,
    validate_remote_authorized_run,
)
from cops.execution.ssh_transport import SSH_PROTOCOL
from cops.execution.supervisor_attestation import (
    SupervisorAttestationError,
    validate_exchange_nonce,
)

REMOTE_WORKER_RELAY_CONFIG_SCHEMA = "cops.remote-worker-relay-config/v1"
DEFAULT_REMOTE_WORKER_RELAY_CONFIG = Path("/etc/cops/remote-worker.json")
_MAX_RELAY_CONFIG_BYTES = 16 * 1024
_DEFAULT_MAX_REQUEST_BYTES = 64 * 1024
_DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
_SUPERVISOR_OVERHEAD_SECONDS = 5.0
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclass(frozen=True)
class RemoteWorkerRelayConfig:
    """Owner-provisioned binding from the SSH forced command to its supervisor."""

    schema_version: str
    expected_host: str
    worker_identity: str
    supervisor_socket_path: Path
    supervisor_uid: int
    supervisor_gid: int
    _file_verified: bool = field(default=False, repr=False, compare=False)

    @classmethod
    def from_file(cls, path: Path | str) -> RemoteWorkerRelayConfig:
        config_path = Path(path)
        if not config_path.is_absolute() or config_path.name in {"", ".", ".."}:
            raise SSHExecutionError("remote worker relay config path is invalid")
        try:
            parent_fd = open_directory_no_symlinks(config_path.parent)
        except SecureDirectoryError as err:
            raise SSHExecutionError("remote worker relay config cannot be opened securely") from err
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_NONBLOCK", 0)
            try:
                fd = os.open(config_path.name, flags, dir_fd=parent_fd)
            except OSError as err:
                raise SSHExecutionError("remote worker relay config cannot be opened securely") from err
        finally:
            os.close(parent_fd)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise SSHExecutionError("remote worker relay config must be a regular file")
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise SSHExecutionError("remote worker relay config must be owned by the current identity")
            if metadata.st_mode & 0o077:
                raise SSHExecutionError("remote worker relay config must be owner-only")
            raw = os.read(fd, _MAX_RELAY_CONFIG_BYTES + 1)
            if len(raw) > _MAX_RELAY_CONFIG_BYTES or os.read(fd, 1):
                raise SSHExecutionError("remote worker relay config exceeds the byte limit")
        finally:
            os.close(fd)
        try:
            document = json.loads(raw, object_pairs_hook=_reject_duplicate_fields)
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise SSHExecutionError("remote worker relay config is not valid UTF-8 JSON") from err
        expected_fields = {
            "schema_version",
            "expected_host",
            "worker_identity",
            "supervisor_socket_path",
            "supervisor_uid",
            "supervisor_gid",
        }
        if not isinstance(document, dict) or set(document) != expected_fields:
            raise SSHExecutionError("remote worker relay config fields do not match the required schema")
        if document["schema_version"] != REMOTE_WORKER_RELAY_CONFIG_SCHEMA:
            raise SSHExecutionError("unsupported remote worker relay config schema version")
        expected_host = document["expected_host"]
        worker_identity = document["worker_identity"]
        if not isinstance(expected_host, str) or _IDENTITY.fullmatch(expected_host) is None:
            raise SSHExecutionError("remote worker relay expected_host is invalid")
        if not isinstance(worker_identity, str) or _IDENTITY.fullmatch(worker_identity) is None:
            raise SSHExecutionError("remote worker relay worker_identity is invalid")
        socket_value = document["supervisor_socket_path"]
        if not isinstance(socket_value, str):
            raise SSHExecutionError("remote worker supervisor socket path is invalid")
        socket_path = Path(socket_value)
        if not socket_path.is_absolute() or ".." in socket_path.parts or socket_path.name in {"", ".", ".."}:
            raise SSHExecutionError("remote worker supervisor socket path is invalid")
        supervisor_uid = document["supervisor_uid"]
        supervisor_gid = document["supervisor_gid"]
        if isinstance(supervisor_uid, bool) or not isinstance(supervisor_uid, int) or supervisor_uid < 0:
            raise SSHExecutionError("remote worker supervisor uid is invalid")
        if isinstance(supervisor_gid, bool) or not isinstance(supervisor_gid, int) or supervisor_gid < 0:
            raise SSHExecutionError("remote worker supervisor gid is invalid")
        if hasattr(os, "geteuid") and supervisor_uid == os.geteuid():
            raise SSHExecutionError("remote worker supervisor must use a distinct identity")
        return cls(
            schema_version=REMOTE_WORKER_RELAY_CONFIG_SCHEMA,
            expected_host=expected_host,
            worker_identity=worker_identity,
            supervisor_socket_path=socket_path,
            supervisor_uid=supervisor_uid,
            supervisor_gid=supervisor_gid,
            _file_verified=True,
        )

    @property
    def is_file_verified(self) -> bool:
        return self._file_verified


@dataclass(frozen=True)
class _ValidatedRemoteExecutionRequest:
    request_id: str
    authorization_id: str
    action_plan: ActionPlan
    timeout_seconds: float
    max_output_bytes: int


class AuthorizedRunLike(Protocol):
    result: RunResult
    approval_receipt: ApprovalConsumptionReceipt


class ReceiptExecutingWorker(Protocol):
    def execute_plan_with_receipt(
        self,
        action_plan: ActionPlan,
        *,
        authorization_id: str,
        workspace_dir: Path | str | None = None,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 65_536,
    ) -> AuthorizedRunLike: ...


@dataclass(frozen=True)
class SSHRemoteExecutionReceiver:
    """Serve SSH relays using one persistent worker and approval-control client."""

    expected_host: str
    expected_worker_identity: str
    worker: ReceiptExecutingWorker
    workspace_dir: Path | str | None = None
    max_request_bytes: int = 64 * 1024
    max_response_bytes: int = 1024 * 1024

    def serve_one(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        serve_one_remote_execution_request(
            expected_host=self.expected_host,
            expected_worker_identity=self.expected_worker_identity,
            worker=self.worker,
            input_stream=input_stream,
            output_stream=output_stream,
            workspace_dir=self.workspace_dir,
            max_request_bytes=self.max_request_bytes,
            max_response_bytes=self.max_response_bytes,
        )


def handle_remote_execution_request(
    document: dict[str, Any],
    *,
    expected_host: str,
    expected_worker_identity: str,
    worker: ReceiptExecutingWorker,
    workspace_dir: Path | str | None = None,
) -> dict[str, Any]:
    request = _validate_remote_execution_request(
        document,
        expected_host=expected_host,
        expected_worker_identity=expected_worker_identity,
    )
    executed = worker.execute_plan_with_receipt(
        request.action_plan,
        authorization_id=request.authorization_id,
        workspace_dir=workspace_dir,
        timeout_seconds=request.timeout_seconds,
        max_output_bytes=request.max_output_bytes,
    )
    authorized_run = RemoteAuthorizedRun(
        result=executed.result,
        approval_receipt=executed.approval_receipt,
    )
    validate_remote_authorized_run(
        authorized_run,
        approved_worker_identity=expected_worker_identity,
        authorization_id=request.authorization_id,
        action_plan=request.action_plan,
    )
    return {
        "protocol": SSH_PROTOCOL,
        "request_id": request.request_id,
        "host": expected_host,
        "worker_id": expected_worker_identity,
        "payload": authorized_run.to_dict(),
    }


def _validate_remote_execution_request(
    document: dict[str, Any],
    *,
    expected_host: str,
    expected_worker_identity: str,
) -> _ValidatedRemoteExecutionRequest:
    expected_fields = {"expected_host", "expected_worker_id", "payload", "protocol", "request_id"}
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise SSHExecutionError("remote execution envelope fields do not match the required schema")
    if document["protocol"] != SSH_PROTOCOL:
        raise SSHExecutionError("unsupported remote execution transport protocol")
    if document["expected_host"] != expected_host or document["expected_worker_id"] != expected_worker_identity:
        raise SSHExecutionError("remote execution endpoint identity mismatch")
    if not isinstance(document["request_id"], str) or not document["request_id"]:
        raise SSHExecutionError("remote execution request_id is invalid")
    payload = document["payload"]
    payload_fields = {
        "schema_version",
        "authorization_id",
        "action_plan",
        "timeout_seconds",
        "max_output_bytes",
        "exchange_nonce",
    }
    if not isinstance(payload, dict) or set(payload) != payload_fields:
        raise SSHExecutionError("remote execution request fields do not match the required schema")
    if payload["schema_version"] != SSH_EXECUTION_REQUEST_SCHEMA:
        raise SSHExecutionError("unsupported remote execution request schema version")
    try:
        validate_exchange_nonce(payload["exchange_nonce"])
    except SupervisorAttestationError as err:
        raise SSHExecutionError("remote execution exchange nonce is invalid") from err
    authorization_id = payload["authorization_id"]
    if not isinstance(authorization_id, str) or not authorization_id:
        raise SSHExecutionError("remote execution authorization_id is invalid")
    timeout_seconds = payload["timeout_seconds"]
    max_output_bytes = payload["max_output_bytes"]
    _validate_execution_limits(timeout_seconds, max_output_bytes)
    if not isinstance(payload["action_plan"], dict):
        raise SSHExecutionError("remote execution action plan is invalid")
    try:
        action_plan = ActionPlan.from_dict(payload["action_plan"])
    except Exception as err:
        raise SSHExecutionError("remote execution action plan is invalid") from err
    return _ValidatedRemoteExecutionRequest(
        request_id=document["request_id"],
        authorization_id=authorization_id,
        action_plan=action_plan,
        timeout_seconds=float(timeout_seconds),
        max_output_bytes=max_output_bytes,
    )


def serve_one_remote_execution_request(
    *,
    expected_host: str,
    expected_worker_identity: str,
    worker: ReceiptExecutingWorker,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    workspace_dir: Path | str | None = None,
    max_request_bytes: int = 64 * 1024,
    max_response_bytes: int = 1024 * 1024,
) -> None:
    if max_request_bytes < 1 or max_response_bytes < 1:
        raise SSHExecutionError("remote execution byte limits must be positive")
    document = _read_one_json_document(input_stream, max_request_bytes=max_request_bytes)
    response = handle_remote_execution_request(
        document,
        expected_host=expected_host,
        expected_worker_identity=expected_worker_identity,
        worker=worker,
        workspace_dir=workspace_dir,
    )
    encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > max_response_bytes:
        raise SSHExecutionError("remote execution response exceeds the byte limit")
    output_stream.write(encoded)
    output_stream.flush()


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise SSHExecutionError("remote execution request contains a duplicate field")
        document[key] = value
    return document


def relay_remote_execution_request(
    document: dict[str, Any],
    *,
    config: RemoteWorkerRelayConfig,
    max_request_bytes: int = _DEFAULT_MAX_REQUEST_BYTES,
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Validate then relay one request to an already-running local supervisor."""

    if not isinstance(config, RemoteWorkerRelayConfig) or not config.is_file_verified:
        raise SSHExecutionError("remote worker relay config is not verified")
    if max_request_bytes < 1 or max_response_bytes < 1:
        raise SSHExecutionError("remote execution byte limits must be positive")
    request = _validate_remote_execution_request(
        document,
        expected_host=config.expected_host,
        expected_worker_identity=config.worker_identity,
    )
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > max_request_bytes:
        raise SSHExecutionError("remote execution request exceeds the byte limit")

    deadline = time.monotonic() + request.timeout_seconds + _SUPERVISOR_OVERHEAD_SECONDS
    supervisor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _verify_supervisor_socket(
            config.supervisor_socket_path,
            supervisor_uid=config.supervisor_uid,
            supervisor_gid=config.supervisor_gid,
        )
        supervisor.settimeout(_remaining(deadline))
        supervisor.connect(str(config.supervisor_socket_path))
        _verify_supervisor_peer(
            supervisor,
            supervisor_uid=config.supervisor_uid,
            supervisor_gid=config.supervisor_gid,
        )
        supervisor.settimeout(_remaining(deadline))
        supervisor.sendall(encoded)
        supervisor.shutdown(socket.SHUT_WR)
        raw = _read_bounded_supervisor_response(
            supervisor,
            max_response_bytes=max_response_bytes,
            deadline=deadline,
        )
    except SSHExecutionError:
        raise
    except (OSError, TimeoutError) as err:
        raise SSHExecutionError("remote worker supervisor exchange failed") from err
    finally:
        supervisor.close()

    try:
        response = json.loads(raw[:-1], object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise SSHExecutionError("remote worker supervisor response is not valid UTF-8 JSON") from err
    expected_fields = {"protocol", "request_id", "host", "worker_id", "payload"}
    if not isinstance(response, dict) or set(response) != expected_fields:
        raise SSHExecutionError("remote worker supervisor response fields do not match the required schema")
    if response["protocol"] != SSH_PROTOCOL or response["request_id"] != request.request_id:
        raise SSHExecutionError("remote worker supervisor response binding mismatch")
    if response["host"] != config.expected_host or response["worker_id"] != config.worker_identity:
        raise SSHExecutionError("remote worker supervisor response identity mismatch")
    payload = response["payload"]
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "authorized_run", "attestation"}:
        raise SSHExecutionError("remote worker supervisor response payload is invalid")
    # The operator verifies the supervisor's attestation before accepting the
    # authorized run. The unprivileged relay must preserve the signed payload.
    return response


def _verify_supervisor_socket(path: Path, *, supervisor_uid: int, supervisor_gid: int) -> None:
    try:
        parent_fd = open_directory_no_symlinks(path.parent)
    except SecureDirectoryError as err:
        raise SSHExecutionError("remote worker supervisor socket cannot be opened securely") from err
    try:
        parent_metadata = os.fstat(parent_fd)
        try:
            metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as err:
            raise SSHExecutionError("remote worker supervisor socket cannot be opened securely") from err
    finally:
        os.close(parent_fd)
    _validate_supervisor_socket_metadata(
        parent_metadata,
        metadata,
        supervisor_uid=supervisor_uid,
        supervisor_gid=supervisor_gid,
    )


def _validate_supervisor_socket_metadata(
    parent_metadata: os.stat_result,
    socket_metadata: os.stat_result,
    *,
    supervisor_uid: int,
    supervisor_gid: int,
) -> None:
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise SSHExecutionError("remote worker supervisor directory is invalid")
    if parent_metadata.st_uid != supervisor_uid or parent_metadata.st_gid != supervisor_gid:
        raise SSHExecutionError("remote worker supervisor directory identity mismatch")
    if stat.S_IMODE(parent_metadata.st_mode) != 0o2710:
        raise SSHExecutionError("remote worker supervisor directory permissions are invalid")
    if not stat.S_ISSOCK(socket_metadata.st_mode):
        raise SSHExecutionError("remote worker supervisor endpoint must be a socket")
    if socket_metadata.st_uid != supervisor_uid or socket_metadata.st_gid != supervisor_gid:
        raise SSHExecutionError("remote worker supervisor socket identity mismatch")
    if stat.S_IMODE(socket_metadata.st_mode) != 0o660:
        raise SSHExecutionError("remote worker supervisor socket permissions are invalid")


def _verify_supervisor_peer(
    supervisor: socket.socket,
    *,
    supervisor_uid: int,
    supervisor_gid: int,
) -> None:
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
        raise SSHExecutionError("remote worker supervisor peer credentials are unavailable")
    credential_size = struct.calcsize("3i")
    try:
        credentials = supervisor.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, credential_size)
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
    except (OSError, struct.error) as err:
        raise SSHExecutionError("remote worker supervisor peer credentials are unavailable") from err
    if peer_pid <= 0 or peer_uid != supervisor_uid or peer_gid != supervisor_gid:
        raise SSHExecutionError("remote worker supervisor peer identity mismatch")


def _read_one_json_document(input_stream: BinaryIO, *, max_request_bytes: int) -> dict[str, Any]:
    if max_request_bytes < 1:
        raise SSHExecutionError("remote execution byte limits must be positive")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = input_stream.read(min(65_536, max_request_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_request_bytes:
            raise SSHExecutionError("remote execution request exceeds the byte limit")
    raw = b"".join(chunks)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise SSHExecutionError("remote execution requires one newline-delimited JSON document")
    try:
        document = json.loads(raw[:-1], object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise SSHExecutionError("remote execution request is not valid UTF-8 JSON") from err
    if not isinstance(document, dict):
        raise SSHExecutionError("remote execution request must be a JSON object")
    return document


def _read_bounded_supervisor_response(
    supervisor: socket.socket,
    *,
    max_response_bytes: int,
    deadline: float,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        supervisor.settimeout(_remaining(deadline))
        chunk = supervisor.recv(min(65_536, max_response_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_response_bytes:
            raise SSHExecutionError("remote worker supervisor response exceeds the byte limit")
    raw = b"".join(chunks)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise SSHExecutionError("remote worker supervisor must return one newline-delimited JSON document")
    return raw


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SSHExecutionError("remote worker supervisor exchange timed out")
    return remaining


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Relay one SSH request to the protected COPS worker supervisor")
    parser.add_argument("--config", type=Path, default=DEFAULT_REMOTE_WORKER_RELAY_CONFIG)
    args = parser.parse_args(argv)
    try:
        document = _read_one_json_document(
            sys.stdin.buffer,
            max_request_bytes=_DEFAULT_MAX_REQUEST_BYTES,
        )
        config = RemoteWorkerRelayConfig.from_file(args.config)
        response = relay_remote_execution_request(document, config=config)
        encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(encoded) > _DEFAULT_MAX_RESPONSE_BYTES:
            raise SSHExecutionError("remote execution response exceeds the byte limit")
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        sys.stderr.write("remote worker request rejected\n")
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
