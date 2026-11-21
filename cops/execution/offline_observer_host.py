"""Read-only Linux host observer for the offline execution gate."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cops.evidence.canonical import canonical, digest

from .filesystem import open_directory_no_symlinks
from .offline_observer import ATTESTATION_SCHEMA, ATTESTATION_TTL_NS, MAX_OBSERVER_MESSAGE_BYTES, parse_observer_request
from .sandbox import LinuxBubblewrapSandbox, SandboxReadinessError

_LOG = logging.getLogger(__name__)
_BUBBLEWRAP = Path("/usr/bin/bwrap")
_PROFILE = "bwrap (enforce)"


def _load_key(path: Path) -> Ed25519PrivateKey:
    parent = open_directory_no_symlinks(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("observer key must be an observer-owned 0600 file")
            return Ed25519PrivateKey.from_private_bytes(source.read(33))
    finally:
        os.close(parent)


def _process_identity(pid: int) -> tuple[int, int]:
    contents = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    _, separator, fields = contents.rpartition(") ")
    values = fields.split()
    if not separator or len(values) < 20:
        raise ValueError("invalid process metadata")
    return int(values[1]), int(values[19])


def _worker_lineage(pid: int, worker_pid: int) -> list[tuple[int, tuple[int, int]]]:
    identities = []
    for _ in range(8):
        if pid <= 1:
            break
        identity = _process_identity(pid)
        identities.append((pid, identity))
        if len(identities) > 1 and pid == worker_pid:
            return identities
        pid = identity[0]
    raise ValueError("paused child does not belong to the worker")


def _measure_gate(request: dict[str, Any], worker_pid: int) -> None:
    gate = request["gate"]
    child_pid = gate["child_pid"]
    lineage = _worker_lineage(child_pid, worker_pid)
    process = Path("/proc") / str(child_pid)
    executable = (process / "exe").stat()
    installed = _BUBBLEWRAP.stat()
    if (
        (executable.st_dev, executable.st_ino) != (installed.st_dev, installed.st_ino)
        or installed.st_uid != 0
        or not stat.S_ISREG(installed.st_mode)
        or installed.st_mode & 0o6022
        or (process / "attr/current").read_text(encoding="ascii").strip() != _PROFILE
        or not LinuxBubblewrapSandbox._execution_gate_is_blocked(**gate)
    ):
        raise ValueError("paused child does not match the installed Bubblewrap profile and gate")
    measured = LinuxBubblewrapSandbox._measure_network_boundary(child_pid)
    if (
        not LinuxBubblewrapSandbox._offline_network_boundary_restricted(measured)
        or digest(measured) != request["isolation_digest"]
        or _worker_lineage(child_pid, worker_pid) != lineage
        or not LinuxBubblewrapSandbox._execution_gate_is_blocked(**gate)
    ):
        raise ValueError("paused child does not match the requested isolation")


def _exchange(
    connection: socket.socket,
    *,
    worker_uid: int,
    worker_gid: int,
    worker_identity: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", credentials)
    if pid <= 1 or uid != worker_uid or gid != worker_gid:
        raise ValueError("unauthorized observer peer")
    deadline = time.monotonic() + ATTESTATION_TTL_NS / 1_000_000_000
    frame = bytearray()
    while len(frame) <= MAX_OBSERVER_MESSAGE_BYTES:
        connection.settimeout(deadline - time.monotonic())
        chunk = connection.recv(min(4096, MAX_OBSERVER_MESSAGE_BYTES + 1 - len(frame)))
        if not chunk:
            break
        frame.extend(chunk)
    request = parse_observer_request(bytes(frame))
    if request["worker_pid"] != pid or request["worker_identity"] != worker_identity:
        raise ValueError("observer peer binding mismatch")
    _measure_gate(request, pid)
    body = {**request, "schema_version": ATTESTATION_SCHEMA, "observed_monotonic_ns": time.monotonic_ns()}
    statement = {**body, "signature": signing_key.sign(canonical(body)).hex()}
    response = canonical(statement) + b"\n"
    if len(response) > MAX_OBSERVER_MESSAGE_BYTES:
        raise ValueError("observer response exceeds its bound")
    connection.settimeout(deadline - time.monotonic())
    connection.sendall(response)
    _LOG.info("observed phase=%s plan=%s isolation=%s", body["phase"], body["plan_digest"], body["isolation_digest"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-path", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--worker-uid", type=int, required=True)
    parser.add_argument("--worker-gid", type=int, required=True)
    parser.add_argument("--worker-identity", required=True)
    args = parser.parse_args()
    uid = os.geteuid()
    if (
        not uid
        or args.worker_uid <= 0
        or args.worker_gid <= 0
        or args.worker_uid == uid
        or not args.worker_identity
        or not all(path.is_absolute() and path.name for path in (args.socket_path, args.signing_key))
    ):
        parser.error("absolute paths and distinct non-root observer and worker accounts are required")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    signing_key = _load_key(args.signing_key)
    directory_fd = open_directory_no_symlinks(args.socket_path.parent)
    try:
        directory_info = os.fstat(directory_fd)
        if (
            directory_info.st_uid != uid
            or directory_info.st_gid != args.worker_gid
            or stat.S_IMODE(directory_info.st_mode) != 0o2710
        ):
            raise ValueError("socket directory must be owned by the observer and worker group with mode 2710")
    finally:
        os.close(directory_fd)

    def stop(_signal: int, _frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    os.umask(0o117)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(os.fspath(args.socket_path))
        try:
            listener.listen(4)
            while True:
                connection, _ = listener.accept()
                with connection:
                    try:
                        _exchange(
                            connection,
                            worker_uid=args.worker_uid,
                            worker_gid=args.worker_gid,
                            worker_identity=args.worker_identity,
                            signing_key=signing_key,
                        )
                    except (OSError, ValueError, SandboxReadinessError) as error:
                        _LOG.warning("observer denied request (%s)", type(error).__name__)
        finally:
            args.socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
