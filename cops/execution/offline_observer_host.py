"""Read-only Linux host observer for the offline execution gate."""

from __future__ import annotations

import argparse
import hashlib
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
_CAT = Path("/usr/bin/cat")
_PROFILE = "bwrap (enforce)"
_LIVE_CAT_PROFILE = "bwrap//&unpriv_bwrap (enforce)"
_STAGED_TOOL = "/cops/tool"
_LIVE_SAMPLE_SCHEMA = "cops.offline-observer-live-sample/v1"


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


def _measure_gate(request: dict[str, Any], worker_pid: int) -> list[tuple[int, tuple[int, int]]]:
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
    return lineage


def _pin_cat(expected_sha256: str) -> int:
    fd = os.open(_CAT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as executable:
        info = os.fstat(executable.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o6022
            or hashlib.file_digest(executable, "sha256").hexdigest() != expected_sha256
        ):
            raise ValueError("live sample executable does not match the root-owned cat pin")
        return info.st_size


def _executable_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _sample_live_cat(
    release: dict[str, Any],
    lineage: list[tuple[int, tuple[int, int]]],
    network_namespace: str,
    cat_size: int,
    cat_sha256: str,
) -> dict[str, Any] | None:
    gate_pid = release["gate"]["child_pid"]
    worker_pid = release["worker_pid"]
    proc_root = Path("/proc")
    children_path = proc_root / str(gate_pid) / "task" / str(gate_pid) / "children"
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        if _worker_lineage(gate_pid, worker_pid) != lineage:
            return None
        children = " ".join(LinuxBubblewrapSandbox._read_proc_lines(children_path)).split()
        if len(children) == 1:
            child_pid = int(children[0])
            proc = proc_root / str(child_pid)
            identity = _process_identity(child_pid)
            if (
                identity[0] == gate_pid
                and (proc / "attr/current").read_text(encoding="ascii").strip() == _LIVE_CAT_PROFILE
                and os.readlink(proc / "exe") == _STAGED_TOOL
            ):
                break
        time.sleep(0.001)
    else:
        return None

    # Bubblewrap binds a staged copy of the approved executable at /cops/tool.
    # Keep its proc descriptor open while measuring its bytes and network state.
    exe_path = proc / "exe"
    fd = os.open(exe_path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size != cat_size
            or hashlib.sha256(source.read(cat_size + 1)).hexdigest() != cat_sha256
            or os.readlink(proc / "ns/net") != network_namespace
        ):
            return None
        measured = LinuxBubblewrapSandbox._measure_network_boundary(child_pid)
        if (
            not LinuxBubblewrapSandbox._offline_network_boundary_restricted(measured)
            or digest(measured) != release["isolation_digest"]
            or _executable_identity(exe_path.stat()) != _executable_identity(info)
            or os.readlink(exe_path) != _STAGED_TOOL
            or os.readlink(proc / "ns/net") != network_namespace
            or (proc / "attr/current").read_text(encoding="ascii").strip() != _LIVE_CAT_PROFILE
            or _process_identity(child_pid) != identity
            or _worker_lineage(gate_pid, worker_pid) != lineage
        ):
            return None
    return {
        "schema_version": _LIVE_SAMPLE_SCHEMA,
        "release_sha256": digest(release),
        "observed_monotonic_ns": time.monotonic_ns(),
        "gate_pid": gate_pid,
        "child_pid": child_pid,
        "child_start_ticks": identity[1],
        "executable_sha256": cat_sha256,
        "isolation": measured,
    }


def _exchange(
    connection: socket.socket,
    *,
    worker_uid: int,
    worker_gid: int,
    worker_identity: str,
    signing_key: Ed25519PrivateKey,
    live_cat: tuple[int, str] | None = None,
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
    lineage = _measure_gate(request, pid)
    sample_release = live_cat is not None and request["phase"] == "release"
    if sample_release:
        network_namespace = os.readlink(Path("/proc") / str(request["gate"]["child_pid"]) / "ns/net")
    body = {**request, "schema_version": ATTESTATION_SCHEMA, "observed_monotonic_ns": time.monotonic_ns()}
    statement = {**body, "signature": signing_key.sign(canonical(body)).hex()}
    response = canonical(statement) + b"\n"
    if len(response) > MAX_OBSERVER_MESSAGE_BYTES:
        raise ValueError("observer response exceeds its bound")
    connection.settimeout(deadline - time.monotonic())
    connection.sendall(response)
    _LOG.info("observed phase=%s plan=%s isolation=%s", body["phase"], body["plan_digest"], body["isolation_digest"])
    if live_cat is not None and sample_release:
        # Deliver EOF to the verifier so the worker can open the gate.
        connection.shutdown(socket.SHUT_WR)
        try:
            sample = _sample_live_cat(statement, lineage, network_namespace, *live_cat)
        except OSError, ValueError, SandboxReadinessError:
            sample = None
        if sample is not None:
            signed_sample = {**sample, "signature": signing_key.sign(canonical(sample)).hex()}
            _LOG.info("observed live cat %s", canonical(signed_sample).decode("ascii"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-path", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--worker-uid", type=int, required=True)
    parser.add_argument("--worker-gid", type=int, required=True)
    parser.add_argument("--worker-identity", required=True)
    parser.add_argument("--live-cat-sha256", help="pin /usr/bin/cat for signed live qualification samples")
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
    live_cat = None
    if args.live_cat_sha256 is not None:
        live_cat = (_pin_cat(args.live_cat_sha256), args.live_cat_sha256)
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
                            live_cat=live_cat,
                        )
                    except (OSError, ValueError, SandboxReadinessError) as error:
                        _LOG.warning("observer denied request (%s)", type(error).__name__)
        finally:
            args.socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
