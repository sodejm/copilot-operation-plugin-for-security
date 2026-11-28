from __future__ import annotations

import os
import socket
import stat
from dataclasses import replace
from pathlib import Path
from threading import Event
from unittest.mock import MagicMock

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops import worker_supervisor as supervisor
from cops.execution.control import ApprovalAuthorityServer, ApprovalControlError
from cops.execution.ssh_transport import SSHTransportError, SSHTransportLimits
from tests.auth_testkit import make_test_approval_authority
from tests.ssh_transport_testkit import make_transport
from tests.test_approval_control_boundary import _plan
from tests.test_worker_supervisor import _config, _Receiver

scenarios("../../specs/features/remote_worker_ssh_transport.feature")


@pytest.fixture
def ssh_context(tmp_path: Path) -> dict[str, object]:
    return {"tmp_path": tmp_path}


@given(
    parsers.parse('a pinned SSH transport for host "{host}" and worker "{worker}"'),
    target_fixture="ssh_context",
)
def pinned_transport(tmp_path: Path, host: str, worker: str) -> dict[str, object]:
    assert host == "worker.example.test"
    transport, _, _ = make_transport(tmp_path, worker_id=worker)
    return {"tmp_path": tmp_path, "transport": transport}


@when("the remote worker returns the matching versioned response")
def matching_response(ssh_context: dict[str, object]) -> None:
    transport = ssh_context["transport"]
    ssh_context["response"] = transport.request({}, request_id="request-bdd")


@when(parsers.parse('the remote worker returns a mismatched "{binding}"'))
def mismatched_response(ssh_context: dict[str, object], binding: str) -> None:
    transport = ssh_context["transport"]
    try:
        transport.request({"mode": f"{binding}-mismatch"}, request_id="request-bdd-mismatch")
    except SSHTransportError as err:
        ssh_context["error"] = err


@when(parsers.parse('the remote exchange exceeds its "{limit}" limit'))
def exceeded_limit(ssh_context: dict[str, object], limit: str) -> None:
    root = ssh_context["tmp_path"]
    limits = SSHTransportLimits(
        timeout_seconds=0.15,
        max_response_bytes=512,
        max_diagnostic_bytes=512,
    )
    transport, _, _ = make_transport(root, limits=limits)
    mode = {"response": "response-overflow", "diagnostic": "diagnostic-overflow", "time": "timeout"}[limit]
    try:
        transport.request({"mode": mode}, request_id="request-bdd-limit")
    except SSHTransportError as err:
        ssh_context["error"] = err


@then("the SSH transport returns the remote payload")
def returns_payload(ssh_context: dict[str, object]) -> None:
    assert ssh_context["response"].payload["result"] == "accepted"


@then("strict host-key verification and forwarding protections were requested")
def strict_options(ssh_context: dict[str, object]) -> None:
    argv = ssh_context["response"].payload["argv"]
    options = {argv[index + 1] for index, argument in enumerate(argv) if argument == "-o"}
    assert "StrictHostKeyChecking=yes" in options
    assert "ClearAllForwardings=yes" in options
    assert "ProxyCommand=none" in options


@then("the SSH transport rejects the response before returning its payload")
def rejects_payload(ssh_context: dict[str, object]) -> None:
    assert isinstance(ssh_context.get("error"), SSHTransportError)
    assert "response" not in ssh_context


@given(parsers.parse('a provisioned "{service}" service socket directory'))
def provisioned_service_socket(ssh_context, monkeypatch, service):
    tmp_path = ssh_context["tmp_path"]
    socket_dir = tmp_path / "socket"
    socket_dir.mkdir()
    directory = socket_dir.stat()

    def with_provisioned_mode(observed):
        if (observed.st_dev, observed.st_ino) == (directory.st_dev, directory.st_ino):
            # Simulate the provisioned Linux setgid directory on every test host.
            return os.stat_result((stat.S_IFDIR | 0o2710, *tuple(observed)[1:]))
        return observed

    original_fstat, original_lstat = os.fstat, os.lstat
    monkeypatch.setattr(os, "fstat", lambda fd: with_provisioned_mode(original_fstat(fd)))
    monkeypatch.setattr(os, "lstat", lambda path, **kwargs: with_provisioned_mode(original_lstat(path, **kwargs)))
    socket_path = socket_dir / "service.sock"
    ssh_context["socket_path"] = socket_path
    if service == "approval authority":
        monkeypatch.setattr("cops.execution.control.sys_platform_linux", lambda: True)
        authority, _, _ = make_test_approval_authority(tmp_path, _plan())
        server = ApprovalAuthorityServer(socket_path, authority)

        def start():
            with server.listener():
                pass
    else:
        assert service == "worker supervisor"
        monkeypatch.setattr(supervisor.sys, "platform", "linux")
        config = replace(
            _config(tmp_path), socket_path=socket_path, supervisor_uid=os.geteuid(), supervisor_gid=os.getegid()
        )
        stop_requested = Event()
        stop_requested.set()

        def start():
            supervisor.serve_forever(config, _Receiver(), stop_requested=stop_requested)

    ssh_context["start_service"] = start


@when(parsers.parse('the service binds a socket with "{mode}" permissions'))
def bind_service_socket(ssh_context, monkeypatch, mode):
    listener = MagicMock()
    listener.__enter__.return_value = listener
    socket_path = ssh_context["socket_path"]
    original_lstat = os.lstat
    original_mask = 0o022
    mask = original_mask
    bound_mode = None

    def umask(value):
        nonlocal mask
        previous, mask = mask, value
        return previous

    def bind(path):
        nonlocal bound_mode
        assert Path(path) == socket_path
        assert mask == 0o117
        bound_mode = (0o777 & ~mask) if mode == "exact" else 0o666

    def lstat(path, **kwargs):
        if path == socket_path and bound_mode is not None:
            return os.stat_result((stat.S_IFSOCK | bound_mode, 1, 1, 1, os.geteuid(), os.getegid(), 0, 0, 0, 0))
        return original_lstat(path, **kwargs)

    listener.bind.side_effect = bind
    monkeypatch.setattr(socket, "socket", lambda *_args: listener)
    monkeypatch.setattr(os, "umask", umask)
    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "chmod", lambda *_args, **_kwargs: pytest.fail("permissions changed after bind"))

    try:
        ssh_context["start_service"]()
    except (ApprovalControlError, supervisor.WorkerSupervisorError) as err:
        ssh_context["startup_error"] = err
    listener.bind.assert_called_once()
    assert mask == original_mask
    ssh_context["listener"] = listener


@then(parsers.parse('the socket listener is "{outcome}" after permission verification'))
def service_socket_outcome(ssh_context, outcome):
    listener = ssh_context["listener"]
    if outcome == "opened":
        assert "startup_error" not in ssh_context
        listener.listen.assert_called_once()
    else:
        assert outcome == "refused"
        assert "mode" in str(ssh_context["startup_error"])
        listener.listen.assert_not_called()
