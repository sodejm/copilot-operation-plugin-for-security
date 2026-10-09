from __future__ import annotations

from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.execution.ssh_transport import SSHTransportError, SSHTransportLimits
from tests.ssh_transport_testkit import make_transport

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
