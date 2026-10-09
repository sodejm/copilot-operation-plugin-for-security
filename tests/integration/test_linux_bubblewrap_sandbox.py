"""Real Linux bubblewrap isolation checks for the production execution sandbox."""

from __future__ import annotations

import errno
import json
import os
import socket
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from cops.execution.sandbox import LinuxBubblewrapSandbox, SandboxReadinessError

pytestmark = [
    pytest.mark.linux_bubblewrap,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="the production bubblewrap boundary is Linux-only",
    ),
]

_BUBBLEWRAP = Path("/usr/bin/bwrap")
_PYTHON = Path("/usr/bin/python3")


@dataclass(frozen=True)
class ReadySandbox:
    sandbox: LinuxBubblewrapSandbox
    workspace: Path


@pytest.fixture
def ready_sandbox(tmp_path: Path) -> ReadySandbox:
    """Require the production boundary on Linux; absence is a gate failure."""
    if not _BUBBLEWRAP.is_file():
        pytest.fail("required Linux isolation gate cannot find /usr/bin/bwrap")
    if os.geteuid() == 0:
        pytest.fail("required Linux isolation gate must run as a non-root worker")

    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    workspace.chmod(0o700)
    sandbox = LinuxBubblewrapSandbox(bubblewrap_path=_BUBBLEWRAP)
    try:
        sandbox.assert_ready("integration-worker", cwd=workspace)
    except SandboxReadinessError as err:
        pytest.fail(f"required Linux isolation readiness failed: {err}")
    return ReadySandbox(sandbox=sandbox, workspace=workspace)


def _open_python() -> int:
    executable = _PYTHON.resolve(strict=True)
    info = executable.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111 == 0:
        pytest.fail("required Linux isolation gate cannot find an executable /usr/bin/python3")
    return os.open(executable, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))


def _run_python(
    ready: ReadySandbox,
    script: str,
    arguments: Sequence[str] = (),
    *,
    env: Mapping[str, str] | None = None,
    operation_env: Mapping[str, str] | None = None,
    capability_fds: tuple[int, ...] = (),
) -> object:
    executable_fd = _open_python()
    try:
        result = ready.sandbox.run(
            [f"/proc/self/fd/{executable_fd}", "-c", script, *arguments],
            cwd=ready.workspace,
            env=env or {},
            operation_env=operation_env,
            timeout_seconds=10.0,
            max_output_bytes=64 * 1024,
            pass_fds=(executable_fd,),
            capability_fds=capability_fds,
        )
    finally:
        os.close(executable_fd)

    assert not result.timed_out
    assert not result.output_limit_exceeded
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return json.loads(result.stdout)


def test_environment_and_host_paths_are_confined(
    ready_sandbox: ReadySandbox,
    tmp_path: Path,
) -> None:
    workspace_sentinel = ready_sandbox.workspace / "workspace-sentinel.txt"
    workspace_sentinel.write_text("workspace-visible", encoding="utf-8")
    host_sentinel = tmp_path / "host-sentinel.txt"
    host_sentinel.write_text("host-private", encoding="utf-8")

    observed = _run_python(
        ready_sandbox,
        """
import json
import os
import pathlib
import sys

host_path = pathlib.Path(sys.argv[1])
try:
    host_value = host_path.read_text(encoding="utf-8")
except OSError:
    host_value = None
print(json.dumps({
    "cwd": os.getcwd(),
    "workspace": pathlib.Path("workspace-sentinel.txt").read_text(encoding="utf-8"),
    "host_value": host_value,
    "host_secret": os.environ.get("COPS_HOST_SECRET"),
    "operation_value": os.environ.get("COPS_OPERATION_VALUE"),
    "etc_visible": pathlib.Path("/etc/passwd").exists(),
}))
""",
        (os.fspath(host_sentinel),),
        env={"LANG": "C", "COPS_HOST_SECRET": "must-not-cross-boundary"},
        operation_env={"COPS_OPERATION_VALUE": "approved-operation-value"},
    )

    assert observed == {
        "cwd": "/work",
        "workspace": "workspace-visible",
        "host_value": None,
        "host_secret": None,
        "operation_value": "approved-operation-value",
        "etc_visible": False,
    }


def test_unrelated_descriptor_and_kernel_resources_are_confined(
    ready_sandbox: ReadySandbox,
    tmp_path: Path,
) -> None:
    host_file = tmp_path / "inherited-descriptor-sentinel.txt"
    host_file.write_text("must-not-be-readable", encoding="utf-8")
    host_fd = os.open(host_file, os.O_RDONLY)
    os.set_inheritable(host_fd, True)
    identity = os.fstat(host_fd)
    try:
        observed = _run_python(
            ready_sandbox,
            """
import json
import os
import resource
import sys

descriptor = int(sys.argv[1])
expected_device = int(sys.argv[2])
expected_inode = int(sys.argv[3])
try:
    descriptor_info = os.fstat(descriptor)
    inherited_identity = (
        descriptor_info.st_dev == expected_device and descriptor_info.st_ino == expected_inode
    )
except OSError:
    inherited_identity = False

status = {}
for line in open("/proc/self/status", encoding="utf-8"):
    if ":" in line:
        key, value = line.split(":", 1)
        status[key] = value.strip()

limits = {
    "as": resource.getrlimit(resource.RLIMIT_AS),
    "nproc": resource.getrlimit(resource.RLIMIT_NPROC),
    "cpu": resource.getrlimit(resource.RLIMIT_CPU),
    "fsize": resource.getrlimit(resource.RLIMIT_FSIZE),
    "nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
    "core": resource.getrlimit(resource.RLIMIT_CORE),
}
print(json.dumps({
    "inherited_identity": inherited_identity,
    "no_new_privs": status.get("NoNewPrivs"),
    "limits": limits,
}))
""",
            (str(host_fd), str(identity.st_dev), str(identity.st_ino)),
        )
    finally:
        os.close(host_fd)

    assert observed["inherited_identity"] is False
    assert observed["no_new_privs"] == "1"
    expected = ready_sandbox.sandbox.resources
    for name, maximum in {
        "as": expected.address_space_bytes,
        "nproc": expected.process_count,
        "cpu": int(expected.cpu_seconds),
        "fsize": expected.file_size_bytes,
        "nofile": expected.open_files,
    }.items():
        soft, hard = observed["limits"][name]
        assert 0 < soft == hard <= maximum
    assert tuple(observed["limits"]["core"]) == (0, 0)


def test_network_and_pid_namespaces_are_new_and_raw_network_is_denied(
    ready_sandbox: ReadySandbox,
) -> None:
    host_network_namespace = os.readlink("/proc/self/ns/net")
    host_pid_namespace = os.readlink("/proc/self/ns/pid")
    observed = _run_python(
        ready_sandbox,
        """
import errno
import json
import os
import socket

raw_errno = None
try:
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
except OSError as err:
    raw_errno = err.errno
else:
    raw_socket.close()
print(json.dumps({
    "net_namespace": os.readlink("/proc/self/ns/net"),
    "pid_namespace": os.readlink("/proc/self/ns/pid"),
    "raw_errno": raw_errno,
}))
""",
    )

    assert observed["net_namespace"] != host_network_namespace
    assert observed["pid_namespace"] != host_pid_namespace
    assert observed["raw_errno"] in {errno.EPERM, errno.EACCES}


def test_unmapped_capability_descriptor_fails_closed(ready_sandbox: ReadySandbox) -> None:
    executable_fd = _open_python()
    capability_fd = os.open(ready_sandbox.workspace, os.O_RDONLY)
    try:
        with pytest.raises(SandboxReadinessError, match="capability"):
            ready_sandbox.sandbox.run(
                [f"/proc/self/fd/{executable_fd}", "-c", "raise SystemExit(0)"],
                cwd=ready_sandbox.workspace,
                env={},
                timeout_seconds=10.0,
                max_output_bytes=4096,
                pass_fds=(executable_fd,),
                capability_fds=(capability_fd,),
            )
    finally:
        os.close(capability_fd)
        os.close(executable_fd)


def test_mapped_egress_broker_socket_is_the_only_capability(
    ready_sandbox: ReadySandbox,
) -> None:
    parent_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        child_socket.sendall(b"broker-ready")
        observed = _run_python(
            ready_sandbox,
            """
import json
import os
import socket

descriptor = int(os.environ["COPS_EGRESS_BROKER_FD"])
broker = socket.socket(fileno=descriptor)
print(json.dumps({"message": broker.recv(64).decode("ascii"), "family": broker.family}))
""",
            operation_env={"COPS_EGRESS_BROKER_FD": str(parent_socket.fileno())},
            capability_fds=(parent_socket.fileno(),),
        )
    finally:
        parent_socket.close()
        child_socket.close()

    assert observed == {"message": "broker-ready", "family": socket.AF_UNIX}
