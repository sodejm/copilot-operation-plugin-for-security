"""Persistent, unprivileged worker behind the pinned SSH relay.

The SSH login account can only send a framed request over the supervisor socket.
Approval creation, verifier keys, and the approval database stay in a separate
authority process reached through the consume-only control client.
"""

from __future__ import annotations

import io
import json
import os
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cops.adapters import ToolAdapterRegistry
from cops.contracts.models import Engagement
from cops.execution.control import ApprovalControlClient
from cops.execution.filesystem import open_directory_no_symlinks
from cops.execution.sandbox import LinuxBubblewrapSandbox
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.execution.worker import IsolatedWorker, WorkerCapabilityInventory
from cops.remote_worker import SSHRemoteExecutionReceiver

CONFIG_SCHEMA = "cops.worker-supervisor-config/v1"
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024


class WorkerSupervisorError(RuntimeError):
    """The supervisor could not establish or preserve its trust boundary."""


def _owner_only_json(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise WorkerSupervisorError("supervisor input path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent = open_directory_no_symlinks(path.parent)
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent)
        finally:
            os.close(parent)
    except OSError as err:
        raise WorkerSupervisorError("supervisor input is unavailable") from err
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise WorkerSupervisorError("supervisor input must be an account-owned regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkerSupervisorError("supervisor input must be owner-only")
        with os.fdopen(descriptor, encoding="utf-8") as source:
            descriptor = -1
            data = json.load(source)
    except (OSError, ValueError) as err:
        raise WorkerSupervisorError("supervisor input is invalid JSON") from err
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(data, dict):
        raise WorkerSupervisorError("supervisor input must be a JSON object")
    return data


@dataclass(frozen=True)
class WorkerSupervisorConfig:
    expected_host: str
    worker_identity: str
    socket_path: Path
    relay_uid: int
    relay_gid: int
    supervisor_uid: int
    supervisor_gid: int
    authority_uid: int
    approval_socket_path: Path
    inventory_path: Path
    engagement_path: Path
    executable_sha256_pins: dict[str, str]

    @classmethod
    def from_file(cls, path: Path | str) -> WorkerSupervisorConfig:
        data = _owner_only_json(Path(path))
        required = {
            "schema_version",
            "expected_host",
            "worker_identity",
            "socket_path",
            "relay_uid",
            "relay_gid",
            "supervisor_uid",
            "supervisor_gid",
            "authority_uid",
            "approval_socket_path",
            "inventory_path",
            "engagement_path",
            "executable_sha256_pins",
        }
        if set(data) != required or data["schema_version"] != CONFIG_SCHEMA:
            raise WorkerSupervisorError("supervisor configuration fields or schema are invalid")
        for key in ("expected_host", "worker_identity"):
            if not isinstance(data[key], str) or not data[key].strip():
                raise WorkerSupervisorError(f"supervisor {key} must be non-empty")
        for key in ("relay_uid", "relay_gid", "supervisor_uid", "supervisor_gid", "authority_uid"):
            if type(data[key]) is not int or data[key] < 1:
                raise WorkerSupervisorError(f"supervisor {key} must be a non-root integer")
        if data["relay_uid"] in (data["supervisor_uid"], data["authority_uid"]):
            raise WorkerSupervisorError("relay, supervisor, and authority require separate UIDs")
        if data["supervisor_uid"] == data["authority_uid"]:
            raise WorkerSupervisorError("supervisor and authority require separate UIDs")
        if (os.geteuid(), os.getegid()) != (data["supervisor_uid"], data["supervisor_gid"]):
            raise WorkerSupervisorError("supervisor account does not match the configured UID/GID")
        for key in ("socket_path", "approval_socket_path", "inventory_path", "engagement_path"):
            if not isinstance(data[key], str) or not Path(data[key]).is_absolute():
                raise WorkerSupervisorError(f"supervisor {key} must be an absolute path")
        pins = data["executable_sha256_pins"]
        if not isinstance(pins, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in pins.items()):
            raise WorkerSupervisorError("supervisor executable pins must be a string mapping")
        return cls(
            expected_host=data["expected_host"],
            worker_identity=data["worker_identity"],
            socket_path=Path(data["socket_path"]),
            relay_uid=data["relay_uid"],
            relay_gid=data["relay_gid"],
            supervisor_uid=data["supervisor_uid"],
            supervisor_gid=data["supervisor_gid"],
            authority_uid=data["authority_uid"],
            approval_socket_path=Path(data["approval_socket_path"]),
            inventory_path=Path(data["inventory_path"]),
            engagement_path=Path(data["engagement_path"]),
            executable_sha256_pins=pins,
        )


def build_receiver(config: WorkerSupervisorConfig) -> SSHRemoteExecutionReceiver:
    """Build the production worker using only provisioned local inputs."""
    inventory = WorkerCapabilityInventory.from_file(
        config.inventory_path, expected_worker_identity=config.worker_identity
    )
    engagement = Engagement.from_dict(_owner_only_json(config.engagement_path))
    control = ApprovalControlClient(
        socket_path=config.approval_socket_path,
        expected_authority_uid=config.authority_uid,
        worker_uid=config.supervisor_uid,
        worker_gid=config.supervisor_gid,
    )
    sandbox = LinuxBubblewrapSandbox(worker_uid=config.supervisor_uid, worker_gid=config.supervisor_gid)
    worker = IsolatedWorker(
        inventory,
        control,
        sandbox,
        scope_guard=ScopeGuard(ScopeDefinition.from_engagement_scope(engagement.scope)),
        adapter_registry=ToolAdapterRegistry(executable_sha256_pins=config.executable_sha256_pins),
    )
    return SSHRemoteExecutionReceiver(
        expected_host=config.expected_host,
        expected_worker_identity=config.worker_identity,
        worker=worker,
    )


def _read_complete_request(connection: socket.socket, deadline: float) -> bytes:
    """Wait for write shutdown before execution, rejecting trailing or partial bytes."""
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WorkerSupervisorError("relay request deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(min(65_536, MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_REQUEST_BYTES:
            raise WorkerSupervisorError("relay request exceeds the byte limit")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise WorkerSupervisorError("relay requires one complete newline-delimited request")
    return bytes(data)


def serve_connection(
    connection: socket.socket,
    config: WorkerSupervisorConfig,
    receiver: SSHRemoteExecutionReceiver,
    *,
    timeout_seconds: float = 30.0,
) -> None:
    """Handle exactly one authenticated relay connection."""
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise WorkerSupervisorError("Linux peer credentials are required")
    raw_credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, peer_uid, peer_gid = struct.unpack("3i", raw_credentials)
    if (peer_uid, peer_gid) != (config.relay_uid, config.relay_gid):
        raise WorkerSupervisorError("relay peer identity mismatch")
    deadline = time.monotonic() + timeout_seconds
    request = _read_complete_request(connection, deadline)
    output = io.BytesIO()
    receiver.serve_one(io.BytesIO(request), output)
    response = output.getvalue()
    if len(response) > MAX_RESPONSE_BYTES or not response.endswith(b"\n") or response.count(b"\n") != 1:
        raise WorkerSupervisorError("worker response framing or byte limit is invalid")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WorkerSupervisorError("relay response deadline exceeded")
    connection.settimeout(remaining)
    connection.sendall(response)


def serve_forever(config: WorkerSupervisorConfig, receiver: SSHRemoteExecutionReceiver) -> None:
    """Bind a pre-provisioned directory and serve a single request per connection."""
    if sys.platform != "linux":
        raise WorkerSupervisorError("production supervisor requires Linux")
    try:
        parent_descriptor = open_directory_no_symlinks(config.socket_path.parent)
        try:
            parent = os.fstat(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as err:
        raise WorkerSupervisorError("supervisor socket directory is unavailable") from err
    if (
        not stat.S_ISDIR(parent.st_mode)
        or (parent.st_uid, parent.st_gid) != (config.supervisor_uid, config.supervisor_gid)
        or stat.S_IMODE(parent.st_mode) != 0o2710
    ):
        raise WorkerSupervisorError("supervisor socket directory ownership or mode is unsafe")
    if config.socket_path.exists() or config.socket_path.is_symlink():
        raise WorkerSupervisorError("supervisor socket path already exists")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        old_umask = os.umask(0o117)
        try:
            listener.bind(str(config.socket_path))
        finally:
            os.umask(old_umask)
        os.chmod(config.socket_path, 0o660)
        bound = os.lstat(config.socket_path)
        if not stat.S_ISSOCK(bound.st_mode) or (bound.st_uid, bound.st_gid) != (
            config.supervisor_uid,
            config.supervisor_gid,
        ):
            raise WorkerSupervisorError("bound supervisor socket identity is unsafe")
        listener.listen(8)
        try:
            while True:
                connection, _ = listener.accept()
                with connection:
                    try:
                        serve_connection(connection, config, receiver)
                    except (OSError, ValueError, RuntimeError):
                        # The relay receives EOF; errors must not expose local paths or secrets.
                        continue
        finally:
            config.socket_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "--config":
        print("usage: python3 -m cops.worker_supervisor --config ABSOLUTE_PATH", file=sys.stderr)
        return 2
    try:
        config = WorkerSupervisorConfig.from_file(args[1])
        receiver = build_receiver(config)
        serve_forever(config, receiver)
    except (OSError, ValueError, RuntimeError):
        print("worker supervisor readiness or service failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
