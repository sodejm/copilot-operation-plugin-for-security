"""Capability validation checks for the production execution sandbox."""

from __future__ import annotations

import os
import socket
from contextlib import contextmanager
from pathlib import Path

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
