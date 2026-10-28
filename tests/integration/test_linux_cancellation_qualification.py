"""Production Linux PID namespace cancellation; unsupported hosts cannot qualify."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

from cops.execution import sandbox as sandbox_module
from cops.execution.process import run_bounded_process
from cops.execution.sandbox import LinuxBubblewrapSandbox, SandboxReadinessError
from tests.cancellation_testkit import SOCKET_HOLDER_SCRIPT, assert_processes_terminated, receive_ready

pytestmark = [
    pytest.mark.linux_bubblewrap,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Linux PID namespace cancellation qualification requires Linux and production bubblewrap",
    ),
]


def _descendants(process_id: int) -> set[int]:
    """Observe host PIDs while the namespace and detached child are still live."""
    children = Path(f"/proc/{process_id}/task/{process_id}/children").read_text(encoding="ascii")
    result = {int(value) for value in children.split()}
    for child in tuple(result):
        result.update(_descendants(child))
    return result


def test_interrupt_kills_detached_namespace_descendant_and_closes_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not Path("/usr/bin/bwrap").is_file():
        pytest.fail("required Linux cancellation gate cannot find /usr/bin/bwrap")
    if os.geteuid() == 0:
        pytest.fail("required Linux cancellation gate must run as a non-root worker")
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    sandbox = LinuxBubblewrapSandbox(bubblewrap_path=Path("/usr/bin/bwrap"))
    try:
        sandbox.assert_ready("cancellation-qualification-worker", cwd=workspace)
    except SandboxReadinessError as err:
        pytest.fail(f"required Linux cancellation readiness failed: {err}")

    parent_socket, child_socket = socket.socketpair()
    executable_fd = os.open(Path("/usr/bin/python3").resolve(strict=True), os.O_RDONLY | os.O_CLOEXEC)
    observed = {}

    def interrupt_after_descendant_ready(process, deadline):
        observed["process"] = process
        child_socket.close()
        ready = receive_ready(parent_socket, deadline)
        assert ready["detached"] is True
        descendants = _descendants(process.pid)
        detached = []
        for descendant in descendants:
            status = Path(f"/proc/{descendant}/status").read_text(encoding="ascii")
            namespace_pids = next(line.split()[1:] for line in status.splitlines() if line.startswith("NSpid:"))
            if int(namespace_pids[-1]) == ready["child"]:
                detached.append(descendant)
        assert len(detached) == 1, "detached namespace child was not observed"
        assert os.getsid(detached[0]) == detached[0], "descendant did not create its separate session"
        observed["descendants"] = descendants
        raise KeyboardInterrupt

    def interrupt_run(command, **kwargs):
        assert kwargs.get("on_started") is None
        return run_bounded_process(command, **{**kwargs, "on_started": interrupt_after_descendant_ready})

    monkeypatch.setattr(sandbox_module, "run_bounded_process", interrupt_run)
    try:
        with pytest.raises(KeyboardInterrupt):
            sandbox.run(
                [
                    f"/proc/self/fd/{executable_fd}",
                    "-c",
                    SOCKET_HOLDER_SCRIPT,
                    str(child_socket.fileno()),
                    "detach",
                    "stay",
                ],
                cwd=workspace,
                env={},
                operation_env={"COPS_EGRESS_BROKER_FD": str(child_socket.fileno())},
                timeout_seconds=10,
                max_output_bytes=4096,
                pass_fds=(executable_fd,),
                capability_fds=(child_socket.fileno(),),
            )

        process = observed["process"]
        assert process.poll() is not None
        assert process.stdout.closed
        assert process.stderr.closed
        assert_processes_terminated({process.pid, *observed["descendants"]})
        parent_socket.settimeout(5)
        assert parent_socket.recv(1) == b"", "cancellation left a namespace capability socket open"
    finally:
        os.close(executable_fd)
        child_socket.close()
        parent_socket.close()
