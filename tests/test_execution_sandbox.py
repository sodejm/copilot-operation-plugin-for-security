"""Capability validation checks for the production execution sandbox."""

from __future__ import annotations

import os
import socket

import pytest

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
