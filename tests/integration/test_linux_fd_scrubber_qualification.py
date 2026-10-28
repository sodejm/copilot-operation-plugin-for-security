"""Qualify the final adapter's descriptor boundary on supported Linux hosts."""

from __future__ import annotations

import json
import os
import socket
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest

from cops.execution.sandbox import LinuxBubblewrapSandbox, SandboxReadinessError

pytestmark = [
    pytest.mark.linux_bubblewrap,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="trusted FD scrubber qualification requires Linux and production bubblewrap",
    ),
]


_DESCRIPTOR_PROBE = """
import json
import os
import socket
import stat

# listdir briefly opens a descriptor of its own. Only report descriptors still
# open after it returns, so that temporary procfs enumeration is not a leak.
descriptors = {}
ancestor_reads = []
for name in os.listdir('/proc/self/fd'):
    descriptor = int(name)
    try:
        mode = os.fstat(descriptor).st_mode
    except OSError:
        continue
    descriptors[descriptor] = 'socket' if stat.S_ISSOCK(mode) else 'directory' if stat.S_ISDIR(mode) else 'other'
    if stat.S_ISDIR(mode):
        try:
            outside = os.open('../outside-workspace-canary', os.O_RDONLY, dir_fd=descriptor)
        except OSError:
            pass
        else:
            with os.fdopen(outside, 'rb') as source:
                ancestor_reads.append(source.read(128) == b'host-only-canary')
        try:
            with open('/proc/self/fd/%d/../outside-workspace-canary' % descriptor, 'rb') as source:
                ancestor_reads.append(source.read(128) == b'host-only-canary')
        except OSError:
            pass

broker_descriptor = os.environ.get('COPS_EGRESS_BROKER_FD')
broker_message = None
broker_family = None
if broker_descriptor is not None:
    with socket.socket(fileno=int(broker_descriptor)) as broker:
        broker.settimeout(2)
        broker_family = int(broker.family)
        received = b''
        while len(received) < len(b'scrubber-ready'):
            chunk = broker.recv(len(b'scrubber-ready') - len(received))
            if not chunk:
                raise RuntimeError('broker closed before the complete qualification message')
            received += chunk
        broker_message = received.decode('ascii')
        broker.sendall(b'adapter-ready')
print(json.dumps({
    'descriptors': descriptors,
    'ancestor_reads': ancestor_reads,
    'broker_descriptor': broker_descriptor,
    'broker_message': broker_message,
    'broker_family': broker_family,
    'host_secret': os.environ.get('COPS_HOST_SECRET'),
    'workspace_visible': os.path.isfile('/work/workspace-canary'),
}))
"""


@pytest.mark.parametrize("with_broker", [False, True], ids=["stdio-only", "stdio-and-broker"])
def test_adapter_retains_only_stdio_and_explicit_broker(tmp_path: Path, with_broker: bool) -> None:
    if not Path("/usr/bin/bwrap").is_file():
        pytest.fail("required Linux FD scrubber gate cannot find /usr/bin/bwrap")
    if os.geteuid() == 0:
        pytest.fail("required Linux FD scrubber gate must run as a non-root worker")
    if not Path("/usr/bin/python3").is_file():
        pytest.fail("required Linux FD scrubber gate cannot find /usr/bin/python3")

    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "workspace-canary").write_text("workspace-visible", encoding="ascii")
    (tmp_path / "outside-workspace-canary").write_bytes(b"host-only-canary")
    sandbox = LinuxBubblewrapSandbox(bubblewrap_path=Path("/usr/bin/bwrap"))
    try:
        sandbox.assert_ready("fd-scrubber-qualification-worker", cwd=workspace)
    except SandboxReadinessError as err:
        pytest.fail(f"required Linux FD scrubber readiness failed: {err}")

    with ExitStack() as stack:
        # Force namespace setup descriptors above the single-digit shell range.
        # A scrubber that only closes 3..9 must fail this qualification.
        while True:
            occupied_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            stack.callback(os.close, occupied_fd)
            if occupied_fd >= 16:
                break
        executable_fd = os.open(Path("/usr/bin/python3").resolve(strict=True), os.O_RDONLY | os.O_CLOEXEC)
        stack.callback(os.close, executable_fd)
        operation_env = {}
        capability_fds = ()
        if with_broker:
            supervisor_socket, adapter_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            stack.enter_context(supervisor_socket)
            stack.enter_context(adapter_socket)
            supervisor_socket.sendall(b"scrubber-ready")
            operation_env["COPS_EGRESS_BROKER_FD"] = str(adapter_socket.fileno())
            capability_fds = (adapter_socket.fileno(),)
        result = sandbox.run(
            [f"/proc/self/fd/{executable_fd}", "-c", _DESCRIPTOR_PROBE],
            cwd=workspace,
            env={"COPS_HOST_SECRET": "must-stay-in-supervisor"},
            operation_env=operation_env,
            timeout_seconds=10,
            max_output_bytes=8192,
            pass_fds=(executable_fd,),
            capability_fds=capability_fds,
        )
        assert not result.timed_out
        assert not result.output_limit_exceeded
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        observed = json.loads(result.stdout)
        descriptors = {int(descriptor): kind for descriptor, kind in observed["descriptors"].items()}
        assert observed["ancestor_reads"] == [], "an inherited directory descriptor exposed a host ancestor"
        assert observed["workspace_visible"] is True
        assert observed["host_secret"] is None
        expected_descriptors = {0, 1, 2}
        if with_broker:
            broker_fd = int(observed["broker_descriptor"])
            assert broker_fd > 2
            expected_descriptors.add(broker_fd)
            assert descriptors[broker_fd] == "socket"
            assert observed["broker_family"] == socket.AF_UNIX
            assert observed["broker_message"] == "scrubber-ready"
            supervisor_socket.settimeout(2)
            received = b""
            while len(received) < len(b"adapter-ready"):
                chunk = supervisor_socket.recv(len(b"adapter-ready") - len(received))
                assert chunk, "adapter closed before the complete qualification message"
                received += chunk
            assert received == b"adapter-ready"
        else:
            assert observed["broker_descriptor"] is None
            assert observed["broker_family"] is None
            assert observed["broker_message"] is None
        assert set(descriptors) == expected_descriptors, "sandbox setup descriptors reached the adapter"
