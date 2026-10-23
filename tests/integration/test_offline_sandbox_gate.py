"""Real procfs checks for the offline sandbox's pre-exec readiness barrier."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import contextmanager

import pytest

from cops.execution.sandbox import LinuxBubblewrapSandbox, OfflineIsolationViolation, SandboxReadinessError

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires Linux procfs")


@contextmanager
def _starting_child(*, retain_socket=False, wrong_gate=False, replace_gate=False):
    info_read, info_write = os.pipe()
    gate_read, gate_write = os.pipe()
    wrong_read, wrong_write = os.pipe()
    script = """
import json, os, socket, sys, time
info, gate, keep, replacement = map(int, sys.argv[1:])
sock = socket.socket()
os.write(info, json.dumps({'child-pid': os.getpid()}).encode())
os.close(info)
time.sleep(0.2)
if not keep:
    sock.close()
if replacement >= 0:
    os.dup2(replacement, gate)
os.read(gate, 1)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(info_write), str(wrong_read if wrong_gate else gate_read), str(int(retain_socket)), str(wrong_read if replace_gate else -1)],
        pass_fds=(info_write, gate_read, wrong_read),
    )
    try:
        yield info_read, gate_read, gate_write, child
    finally:
        child.kill()
        child.wait(timeout=5)
        for fd in (info_read, info_write, gate_read, gate_write, wrong_read, wrong_write):
            os.close(fd)


def test_pid_metadata_does_not_measure_setup_socket():
    with _starting_child() as (info, gate, writer, child):
        observation = LinuxBubblewrapSandbox._observe_blocked_child(
            info, time.monotonic() + 3, gate_fd=gate, gate_writer=writer
        )
        assert observation["measured"]["socket_fds"] == 0
        assert child.poll() is None


def test_socket_remaining_at_gate_is_measured_once_and_rejected(monkeypatch):
    measure = LinuxBubblewrapSandbox._measure_network_boundary
    measurements = []

    def record_measurement(pid):
        measured = measure(pid)
        measurements.append(measured)
        return measured

    monkeypatch.setattr(LinuxBubblewrapSandbox, "_measure_network_boundary", record_measurement)
    with _starting_child(retain_socket=True) as (info, gate, writer, child):
        observation = LinuxBubblewrapSandbox._observe_blocked_child(
            info, time.monotonic() + 3, gate_fd=gate, gate_writer=writer
        )
        assert observation["measured"]["socket_fds"] == 1
        recorded = []
        with pytest.raises(OfflineIsolationViolation, match="network channel"):
            LinuxBubblewrapSandbox._authorize_offline_observation(observation, None, recorded.append)
        assert recorded == [observation]
        assert measurements == [observation["measured"]]
        assert child.poll() is None


@pytest.mark.parametrize("replace_gate", [False, True])
def test_wrong_gate_cannot_trigger_measurement(monkeypatch, replace_gate):
    def unexpected_measurement(pid):
        pytest.fail("network boundary measured before execution gate was proven")

    monkeypatch.setattr(LinuxBubblewrapSandbox, "_measure_network_boundary", unexpected_measurement)
    with _starting_child(wrong_gate=not replace_gate, replace_gate=replace_gate) as (info, gate, writer, child):
        expected = "identity differs" if replace_gate else "deadline"
        with pytest.raises(SandboxReadinessError, match=expected):
            LinuxBubblewrapSandbox._observe_blocked_child(
                info, time.monotonic() + 1, gate_fd=gate, gate_writer=writer
            )
        assert child.poll() is None
