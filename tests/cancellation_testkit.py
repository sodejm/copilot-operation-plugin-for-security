"""Synchronized child/socket probes for cancellation qualification tests."""

from __future__ import annotations

import json
import socket
import subprocess
import time

SOCKET_HOLDER_SCRIPT = r"""
import json
import os
import socket
import sys
import time

channel = socket.socket(fileno=int(sys.argv[1]))
detach = sys.argv[2] == "detach"
exit_leader = sys.argv[3] == "exit"
read_fd, write_fd = os.pipe()
child_pid = os.fork()
if child_pid == 0:
    os.close(read_fd)
    if detach:
        os.setsid()
    os.write(write_fd, b"ready")
    os.close(write_fd)
    while True:
        time.sleep(60)
os.close(write_fd)
assert os.read(read_fd, 5) == b"ready"
os.close(read_fd)
channel.sendall(json.dumps({"leader": os.getpid(), "child": child_pid, "detached": detach}).encode() + b"\n")
if exit_leader:
    os._exit(0)
while True:
    time.sleep(60)
"""


def receive_ready(channel: socket.socket, deadline: float) -> dict[str, object]:
    """Wait for the descendant's handshake, bounded by the process deadline."""
    payload = bytearray()
    while not payload.endswith(b"\n"):
        remaining = min(5.0, deadline - time.monotonic())
        assert remaining > 0, "cancellation probe did not become ready"
        channel.settimeout(remaining)
        chunk = channel.recv(4096)
        assert chunk, "cancellation probe exited before its descendant was ready"
        payload.extend(chunk)
        assert len(payload) <= 4096, "invalid cancellation probe handshake"
    return json.loads(payload)


def assert_processes_terminated(process_ids: set[int]) -> None:
    """Require every observed process to be gone or a nonexecuting zombie."""
    assert process_ids
    deadline = time.monotonic() + 5.0
    while True:
        live = set()
        for process_id in process_ids:
            result = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(process_id)],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            assert result.returncode in (0, 1), "process observation failed"
            assert not result.stderr, "process observation reported an error"
            states = result.stdout.split()
            if any(not state.startswith("Z") for state in states):
                live.add(process_id)
        if not live:
            return
        assert time.monotonic() < deadline, f"cancellation left executing processes: {sorted(live)}"
        time.sleep(0.01)
