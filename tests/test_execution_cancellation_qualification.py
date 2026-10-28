"""Portable POSIX process cleanup evidence, without claiming OS sandboxing."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

from cops.execution.process import run_bounded_process
from tests.cancellation_testkit import SOCKET_HOLDER_SCRIPT, assert_processes_terminated, receive_ready

pytestmark = pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups and descriptor inheritance")


@pytest.mark.parametrize("leader_exits", [False, True], ids=["live-leader", "exited-leader"])
def test_interrupt_reaps_leader_and_terminates_socket_holding_descendant(tmp_path: Path, leader_exits: bool) -> None:
    parent_socket, child_socket = socket.socketpair()
    observed = {}

    def interrupt_after_descendant_ready(process, deadline):
        observed["process"] = process
        child_socket.close()
        ready = receive_ready(parent_socket, deadline)
        assert ready["leader"] == process.pid
        observed["child"] = ready["child"]
        if leader_exits:
            assert process.wait(timeout=5) == 0
        raise KeyboardInterrupt

    try:
        with pytest.raises(KeyboardInterrupt):
            run_bounded_process(
                [
                    sys.executable,
                    "-c",
                    SOCKET_HOLDER_SCRIPT,
                    str(child_socket.fileno()),
                    "attached",
                    "exit" if leader_exits else "stay",
                ],
                cwd=tmp_path,
                env={},
                timeout_seconds=10,
                max_output_bytes=4096,
                pass_fds=(child_socket.fileno(),),
                on_started=interrupt_after_descendant_ready,
            )

        process = observed["process"]
        assert process.poll() is not None
        assert process.stdout.closed
        assert process.stderr.closed
        assert_processes_terminated({process.pid, observed["child"]})
        parent_socket.settimeout(5)
        assert parent_socket.recv(1) == b"", "cancellation left an inherited socket open"
    finally:
        child_socket.close()
        parent_socket.close()
