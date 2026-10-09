from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

import cops.execution.ssh_transport as ssh_transport_module
from cops.execution.ssh_transport import (
    SSH_PROTOCOL,
    SSHRemoteEndpoint,
    SSHRemoteTransport,
    SSHTransportError,
    SSHTransportLimits,
)
from tests.ssh_transport_testkit import make_fake_ssh, make_transport


def test_transport_returns_only_exactly_bound_response(tmp_path: Path) -> None:
    transport, marker, _ = make_transport(tmp_path)

    response = transport.request({"action_plan": {"plan_id": "plan-01"}}, request_id="request-01")

    assert marker.read_text(encoding="utf-8") == "invoked"
    assert response.request_id == "request-01"
    assert response.host == "worker.example.test"
    assert response.worker_id == "worker-lab-01"
    assert response.payload["result"] == "accepted"
    assert response.payload["request"] == {
        "expected_host": "worker.example.test",
        "expected_worker_id": "worker-lab-01",
        "payload": {"action_plan": {"plan_id": "plan-01"}},
        "protocol": SSH_PROTOCOL,
        "request_id": "request-01",
    }


def test_transport_invokes_ssh_with_strict_pinned_configuration(tmp_path: Path) -> None:
    transport, _, _ = make_transport(tmp_path)

    response = transport.request({}, request_id="request-options")

    argv = response.payload["argv"]
    options = {argv[index + 1] for index, argument in enumerate(argv) if argument == "-o"}
    assert argv[:2] == ["-F", "/dev/null"]
    assert "BatchMode=yes" in options
    assert "StrictHostKeyChecking=yes" in options
    assert "GlobalKnownHostsFile=/dev/null" in options
    assert "VerifyHostKeyDNS=no" in options
    assert "CanonicalizeHostname=no" in options
    assert "ProxyCommand=none" in options
    assert "ProxyJump=none" in options
    assert "PermitLocalCommand=no" in options
    assert "ClearAllForwardings=yes" in options
    assert "PasswordAuthentication=no" in options
    assert "KbdInteractiveAuthentication=no" in options
    assert "GSSAPIAuthentication=no" in options
    assert "HostKeyAlgorithms=ssh-ed25519" in options
    assert response.payload["pin"] == "worker.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n"
    assert response.payload["pin_mode"] == 0o600
    assert argv[-2:] == ["worker.example.test", "python3 -m cops.remote_worker"]


def test_transport_launches_validated_executable_after_configured_path_is_swapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, marker, _ = make_transport(tmp_path)
    executable = tmp_path / "fake-ssh"
    malicious_marker = tmp_path / "substitute-invoked"
    substitute = tmp_path / "substitute-ssh"
    substitute.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\n"
        f"Path({os.fspath(malicious_marker)!r}).write_text('invoked', encoding='utf-8')\n"
        "raise SystemExit(91)\n",
        encoding="utf-8",
    )
    substitute.chmod(0o700)
    original_popen = ssh_transport_module.subprocess.Popen
    launched: dict[str, object] = {}

    def swap_then_launch(*args: object, **kwargs: object) -> object:
        executable.replace(tmp_path / "validated-ssh")
        substitute.replace(executable)
        launched["command"] = args[0]
        launched["pass_fds"] = kwargs.get("pass_fds", ())
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(ssh_transport_module.subprocess, "Popen", swap_then_launch)

    response = transport.request({}, request_id="request-executable-swap")

    assert response.payload["result"] == "accepted"
    assert marker.read_text(encoding="utf-8") == "invoked"
    assert not malicious_marker.exists()
    if Path("/proc/self/fd").is_dir():
        command = launched["command"]
        pass_fds = launched["pass_fds"]
        assert isinstance(command, list)
        assert isinstance(pass_fds, tuple)
        descriptor_path = Path(command[0])
        assert descriptor_path.parent == Path("/proc/self/fd")
        assert int(descriptor_path.name) in pass_fds


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("protocol-mismatch", "protocol does not match"),
        ("request-mismatch", "request identifier does not match"),
        ("host-mismatch", "host identity does not match"),
        ("worker-mismatch", "worker identity does not match"),
        ("extra-field", "envelope is malformed"),
    ],
)
def test_transport_rejects_response_binding_mismatch(tmp_path: Path, mode: str, message: str) -> None:
    transport, _, _ = make_transport(tmp_path)

    with pytest.raises(SSHTransportError, match=message):
        transport.request({"mode": mode}, request_id="request-bindings")


def test_transport_rejects_mismatched_host_pin_before_launch(tmp_path: Path) -> None:
    transport, marker, _ = make_transport(tmp_path, pin_host="substitute.example.test")

    with pytest.raises(SSHTransportError, match="does not match the configured endpoint"):
        transport.request({}, request_id="request-pin")

    assert not marker.exists()


@pytest.mark.parametrize(
    "pin_line",
    [
        "*.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n",
        "|1|hash|hash ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n",
        "@cert-authority worker.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n",
        "worker.example.test,other.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n",
        "worker.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\nother ssh-ed25519 dGVzdA==\n",
    ],
)
def test_transport_rejects_ambiguous_host_pins_before_launch(tmp_path: Path, pin_line: str) -> None:
    transport, marker, known_hosts = make_transport(tmp_path)
    known_hosts.write_text(pin_line, encoding="ascii")
    known_hosts.chmod(0o600)

    with pytest.raises(SSHTransportError):
        transport.request({}, request_id="request-pin-format")

    assert not marker.exists()


def test_transport_rejects_symlinked_host_pin_before_launch(tmp_path: Path) -> None:
    transport, marker, known_hosts = make_transport(tmp_path)
    target = tmp_path / "actual-pin"
    known_hosts.replace(target)
    known_hosts.symlink_to(target)

    with pytest.raises(SSHTransportError, match="cannot be opened securely"):
        transport.request({}, request_id="request-pin-link")

    assert not marker.exists()


def test_transport_rejects_group_readable_host_pin_before_launch(tmp_path: Path) -> None:
    transport, marker, known_hosts = make_transport(tmp_path)
    known_hosts.chmod(0o640)

    with pytest.raises(SSHTransportError, match="owner-only regular file"):
        transport.request({}, request_id="request-pin-mode")

    assert not marker.exists()


def test_transport_rejects_oversized_request_before_launch(tmp_path: Path) -> None:
    transport, marker, _ = make_transport(
        tmp_path,
        limits=SSHTransportLimits(max_request_bytes=128),
    )

    with pytest.raises(SSHTransportError, match="request exceeds"):
        transport.request({"opaque": "x" * 1000}, request_id="request-too-large")

    assert not marker.exists()


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("response-overflow", "response exceeds"),
        ("diagnostic-overflow", "diagnostics exceed"),
    ],
)
def test_transport_bounds_each_output_stream(tmp_path: Path, mode: str, message: str) -> None:
    transport, _, _ = make_transport(
        tmp_path,
        limits=SSHTransportLimits(max_response_bytes=512, max_diagnostic_bytes=512),
    )

    with pytest.raises(SSHTransportError, match=message) as raised:
        transport.request({"mode": mode}, request_id="request-output-limit")

    assert "credential" not in str(raised.value)
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize(
    ("leader_exited", "group_probe", "should_raise"),
    [
        (False, "gone", True),
        (True, "gone", False),
        (True, "present", True),
        (True, "inaccessible", True),
    ],
)
def test_terminate_process_group_only_ignores_permission_race_when_group_is_gone(
    monkeypatch: pytest.MonkeyPatch,
    leader_exited: bool,
    group_probe: str,
    should_raise: bool,
) -> None:
    class Process:
        def poll(self) -> int | None:
            return 0 if leader_exited else None

    def deny_kill(_group: int, requested_signal: int) -> None:
        if requested_signal == 0:
            if group_probe == "gone":
                raise ProcessLookupError("process group is gone")
            if group_probe == "inaccessible":
                raise PermissionError("process group is inaccessible")
            return
        raise PermissionError("process group could not be terminated")

    monkeypatch.setattr(ssh_transport_module.os, "killpg", deny_kill)
    if should_raise:
        with pytest.raises(PermissionError):
            ssh_transport_module._terminate_process_group(Process(), 123)
    else:
        ssh_transport_module._terminate_process_group(Process(), 123)


def test_transport_enforces_total_timeout_and_suppresses_partial_output(tmp_path: Path) -> None:
    transport, _, _ = make_transport(
        tmp_path,
        limits=SSHTransportLimits(timeout_seconds=0.15),
    )
    started = time.monotonic()

    with pytest.raises(SSHTransportError, match="time limit") as raised:
        transport.request({"mode": "timeout"}, request_id="request-timeout")

    assert time.monotonic() - started < 2
    assert "credential" not in str(raised.value)


def test_transport_does_not_return_remote_diagnostics_or_local_paths(tmp_path: Path) -> None:
    transport, _, _ = make_transport(tmp_path)

    with pytest.raises(SSHTransportError, match="exit status 23") as raised:
        transport.request({"mode": "nonzero"}, request_id="request-nonzero")

    message = str(raised.value)
    assert "do-not-return" not in message
    assert os.fspath(tmp_path) not in message


def test_transport_rejects_malformed_response(tmp_path: Path) -> None:
    transport, _, _ = make_transport(tmp_path)

    with pytest.raises(SSHTransportError, match="not valid JSON"):
        transport.request({"mode": "malformed"}, request_id="request-malformed")


def test_non_default_port_requires_bracketed_pin(tmp_path: Path) -> None:
    executable, _ = make_fake_ssh(tmp_path)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("[192.0.2.10]:2222 ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n", encoding="ascii")
    known_hosts.chmod(0o600)
    endpoint = SSHRemoteEndpoint(
        host="192.0.2.10",
        port=2222,
        username="worker",
        worker_id="worker-01",
        known_hosts_path=known_hosts,
        remote_command=("cops-worker",),
    )

    response = SSHRemoteTransport(endpoint, ssh_executable=executable).request({}, request_id="request-port")

    assert response.host == "192.0.2.10"
    assert response.payload["pin"].startswith("[192.0.2.10]:2222 ")


@pytest.mark.parametrize(
    "host",
    ["Worker.EXAMPLE.test", "worker.example.test.", "worker..example.test", "192.168.001.001", "host name"],
)
def test_endpoint_rejects_noncanonical_host(host: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="canonical"):
        SSHRemoteEndpoint(
            host=host,
            port=22,
            username="worker",
            worker_id="worker-01",
            known_hosts_path=tmp_path / "known_hosts",
            remote_command=("worker",),
        )
