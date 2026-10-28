"""Capability validation checks for the production execution sandbox."""

from __future__ import annotations

import os
import socket
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import cops.execution.sandbox as sandbox_module
from cops.execution.process import BoundedProcessResult
from cops.execution.sandbox import LinuxBubblewrapSandbox, SandboxReadinessError


def _validate(capability_fds: tuple[int, ...], operation_env: dict[str, str] | None) -> None:
    executable_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        LinuxBubblewrapSandbox._validate_fds(executable_fd, capability_fds, operation_env)
    finally:
        os.close(executable_fd)


def test_capability_requires_exact_broker_environment_mapping() -> None:
    broker_parent, broker_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(SandboxReadinessError, match="mapped egress broker"):
            _validate((broker_child.fileno(),), None)
        with pytest.raises(SandboxReadinessError, match="mapped egress broker"):
            _validate(
                (broker_child.fileno(),),
                {"COPS_EGRESS_BROKER_FD": str(broker_parent.fileno())},
            )
        with pytest.raises(SandboxReadinessError, match="environment requires"):
            _validate((), {"COPS_EGRESS_BROKER_FD": str(broker_child.fileno())})
    finally:
        broker_parent.close()
        broker_child.close()


def test_mapped_connected_unix_stream_broker_is_accepted() -> None:
    broker_parent, broker_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _validate(
            (broker_child.fileno(),),
            {"COPS_EGRESS_BROKER_FD": str(broker_child.fileno())},
        )
    finally:
        broker_parent.close()
        broker_child.close()


def test_non_socket_capability_is_rejected() -> None:
    directory_fd = os.open(".", os.O_RDONLY)
    try:
        with pytest.raises(SandboxReadinessError, match="connected AF_UNIX"):
            _validate(
                (directory_fd,),
                {"COPS_EGRESS_BROKER_FD": str(directory_fd)},
            )
    finally:
        os.close(directory_fd)


def test_sandbox_rejects_replaced_workspace_before_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    expected_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    executable_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        workspace.rename(tmp_path / "original-workspace")
        workspace.mkdir(mode=0o700)
        monkeypatch.setattr(LinuxBubblewrapSandbox, "_validate_host", lambda self: None)

        with pytest.raises(SandboxReadinessError, match="workspace changed after preflight"):
            LinuxBubblewrapSandbox().run(
                [f"/proc/self/fd/{executable_fd}"],
                cwd=workspace,
                env={},
                timeout_seconds=1,
                max_output_bytes=1024,
                pass_fds=(executable_fd,),
                expected_workspace_fd=expected_fd,
            )

        assert list(workspace.iterdir()) == []
    finally:
        os.close(executable_fd)
        os.close(expected_fd)


def test_inet_and_unconnected_unix_capabilities_are_rejected() -> None:
    inet_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(SandboxReadinessError, match="AF_UNIX"):
            _validate(
                (inet_socket.fileno(),),
                {"COPS_EGRESS_BROKER_FD": str(inet_socket.fileno())},
            )
        with pytest.raises(SandboxReadinessError, match="connected AF_UNIX"):
            _validate(
                (unix_socket.fileno(),),
                {"COPS_EGRESS_BROKER_FD": str(unix_socket.fileno())},
            )
    finally:
        inet_socket.close()
        unix_socket.close()


def test_bubblewrap_credential_environment_stays_out_of_process_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "private-credential-value"
    argument_path = tmp_path / "bubblewrap-arguments"
    argument_fds: list[int] = []

    def open_argument_fd(_name: str, *, flags: int) -> int:
        assert flags
        return os.open(argument_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)

    @contextmanager
    def held_executable():
        descriptor = os.open(os.devnull, os.O_RDONLY)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    monkeypatch.setattr(sandbox_module.os, "memfd_create", open_argument_fd, raising=False)
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_validate_host", lambda self: None)
    monkeypatch.setattr(
        LinuxBubblewrapSandbox,
        "_open_private_workspace",
        staticmethod(lambda cwd: os.open(cwd, os.O_RDONLY)),
    )
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_held_bubblewrap", lambda self: held_executable())
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_held_prlimit", lambda self: held_executable())
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_held_fd_scrubber", lambda self: held_executable())

    def observe_launch(command, **kwargs):
        assert secret not in "\0".join(command)
        assert kwargs["env"] == {}
        argument_fd = int(command[command.index("--args") + 1])
        assert argument_fd in kwargs["pass_fds"]
        argument_fds.append(argument_fd)
        encoded = os.read(argument_fd, 4096)
        assert b"--setenv\0COPS_CREDENTIAL_SERVICE_TOKEN\0" + secret.encode() + b"\0" in encoded
        return BoundedProcessResult(b"", b"", 0, False, False)

    monkeypatch.setattr(sandbox_module, "run_bounded_process", observe_launch)
    executable_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        sandbox = LinuxBubblewrapSandbox()
        result = sandbox.run(
            [f"/proc/self/fd/{executable_fd}"],
            cwd=tmp_path,
            env={},
            timeout_seconds=1,
            max_output_bytes=1024,
            pass_fds=(executable_fd,),
            operation_env={"COPS_CREDENTIAL_SERVICE_TOKEN": secret},
        )
        assert result.returncode == 0
        assert len(argument_fds) == 1
        with pytest.raises(OSError):
            os.fstat(argument_fds[0])
    finally:
        os.close(executable_fd)


@pytest.mark.parametrize("with_broker", [False, True], ids=["stdio-only", "stdio-and-broker"])
def test_adapter_launch_routes_through_trusted_fd_scrubber(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_broker: bool
) -> None:
    """Assert launcher wiring without treating a mocked launch as Linux evidence."""
    argument_path = tmp_path / "bubblewrap-arguments"

    def open_argument_fd(_name: str, *, flags: int) -> int:
        assert flags
        return os.open(argument_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)

    @contextmanager
    def held_executable():
        descriptor = os.open(os.devnull, os.O_RDONLY)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    monkeypatch.setattr(sandbox_module.os, "memfd_create", open_argument_fd, raising=False)
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_validate_host", lambda self: None)
    monkeypatch.setattr(
        LinuxBubblewrapSandbox,
        "_open_private_workspace",
        staticmethod(lambda cwd: os.open(cwd, os.O_RDONLY)),
    )
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_held_bubblewrap", lambda self: held_executable())
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_held_prlimit", lambda self: held_executable())
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_held_fd_scrubber", lambda self: held_executable())
    adapter_arguments = ["--literal", "; touch /work/unapproved", "$(unapproved)", "space separated"]
    launches = []
    with ExitStack() as stack:
        executable_fd = os.open(os.devnull, os.O_RDONLY)
        stack.callback(os.close, executable_fd)
        capability_fds = ()
        operation_env = {}
        if with_broker:
            supervisor_socket, adapter_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            stack.enter_context(supervisor_socket)
            stack.enter_context(adapter_socket)
            capability_fds = (adapter_socket.fileno(),)
            operation_env["COPS_EGRESS_BROKER_FD"] = str(adapter_socket.fileno())

        def observe_launch(command, **kwargs):
            launches.append(command)
            separator = command.index("--")
            payload = command[separator + 1 :]
            assert payload[0] == "/cops/limit"
            assert payload[1].startswith("--nproc=")
            assert payload[2:] == [
                "--",
                "/cops/launcher",
                "-c",
                sandbox_module._FD_SCRUBBER,
                "cops-fd-scrubber",
                str(capability_fds[0]) if with_broker else "none",
                "/cops/tool",
                *adapter_arguments,
            ]
            assert kwargs["env"] == {}
            assert kwargs["defer_process_limit"] is True
            # Setup descriptors must reach bwrap to construct its namespace;
            # Linux qualification checks they do not reach the final adapter.
            inherited = set(kwargs["pass_fds"])
            assert len(inherited) == 6 + len(capability_fds)
            assert executable_fd in inherited
            assert inherited.issuperset(capability_fds)
            argument_fd = int(command[command.index("--args") + 1])
            assert argument_fd in inherited
            encoded_environment = os.read(argument_fd, 4096)
            if with_broker:
                assert (
                    b"--setenv\0COPS_EGRESS_BROKER_FD\0" + str(capability_fds[0]).encode() + b"\0"
                    in encoded_environment
                )
            else:
                assert b"COPS_EGRESS_BROKER_FD" not in encoded_environment
            return BoundedProcessResult(b"", b"", 0, False, False)

        monkeypatch.setattr(sandbox_module, "run_bounded_process", observe_launch)
        result = LinuxBubblewrapSandbox().run(
            [f"/proc/self/fd/{executable_fd}", *adapter_arguments],
            cwd=tmp_path,
            env={},
            timeout_seconds=1,
            max_output_bytes=1024,
            pass_fds=(executable_fd,),
            operation_env=operation_env,
            capability_fds=capability_fds,
        )
        assert result.returncode == 0
        assert len(launches) == 1


def test_execution_gate_rejects_unsupported_syscall_abi(monkeypatch):
    monkeypatch.setattr(sandbox_module.os, "uname", lambda: SimpleNamespace(machine="unknown"), raising=False)
    with pytest.raises(SandboxReadinessError, match="ABI is unsupported"):
        LinuxBubblewrapSandbox._wait_for_execution_gate(1, -1, -1, time.monotonic() + 1)


@pytest.mark.parametrize("observation", [[], ["invalid"], ["0 not-hex 0x0 0x1 0x0 0x0 0x0 0x0 0x0"]])
def test_execution_gate_rejects_malformed_procfs(monkeypatch, observation):
    monkeypatch.setattr(sandbox_module.os, "uname", lambda: SimpleNamespace(machine="x86_64"), raising=False)
    monkeypatch.setattr(LinuxBubblewrapSandbox, "_read_proc_lines", lambda path: observation)
    reader, writer = os.pipe()
    try:
        with pytest.raises(SandboxReadinessError, match="observation is invalid"):
            LinuxBubblewrapSandbox._wait_for_execution_gate(1, reader, writer, time.monotonic() + 1)
    finally:
        os.close(reader)
        os.close(writer)


def test_execution_gate_rejects_unavailable_procfs(monkeypatch):
    monkeypatch.setattr(sandbox_module.os, "uname", lambda: SimpleNamespace(machine="x86_64"), raising=False)

    def unavailable(path):
        raise SandboxReadinessError("offline sandbox namespace observation is unavailable")

    monkeypatch.setattr(LinuxBubblewrapSandbox, "_read_proc_lines", unavailable)
    reader, writer = os.pipe()
    try:
        with pytest.raises(SandboxReadinessError, match="observation is unavailable"):
            LinuxBubblewrapSandbox._wait_for_execution_gate(1, reader, writer, time.monotonic() + 1)
    finally:
        os.close(reader)
        os.close(writer)
