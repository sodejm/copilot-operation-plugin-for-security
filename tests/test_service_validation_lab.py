from __future__ import annotations

import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from cops.discovery import lab_service_provider_registry
from cops.discovery import service_validation_lab as lab
from cops.discovery.service_validation_lab import _Case, _read_wire_request, _start_fixture

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY_ROOT / "scripts" / "service_validation_loopback_example.py"
EXPECTED_ROUTES = {
    "http": "web-api-inventory-and-replay",
    "ssh": "network-remote-and-file-services",
    "redis": "network-data-services",
    "smtp": "network-messaging-services",
    "docker-api": "network-developer-interfaces",
    "dns": "network-infrastructure-services",
    "socks": "network-legacy-and-proxy-services",
}
EXPECTED_PROTOCOL_EVIDENCE = {
    "http": "HTTP GET /health response",
    "ssh": "SSH identification exchange",
    "redis": "Redis PING response",
    "smtp": "SMTP EHLO exchange",
    "docker-api": "Docker Engine GET /version response",
    "dns": "DNS-over-TCP query response",
    "socks": "SOCKS5 method negotiation",
}


def run_public_journey(state_directory: Path) -> dict:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--state-dir", str(state_directory)],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(completed.stdout)


def assert_complete_public_journey(report: dict) -> None:
    assert report["journey"] == ["discovery", "route", "investigate", "validate", "report"]
    assert report["external_targets_supported"] is False
    assert {entry["service"]: entry["skill_id"] for entry in report["registry"]} == EXPECTED_ROUTES

    services = {entry["case_id"]: entry for entry in report["services"]}
    assert len(services) == 8
    assert all(entry["discovered"]["nonstandard_port"] for entry in services.values())
    assert {entry["route"]["service"]: entry["route"]["skill_id"] for entry in services.values()} == EXPECTED_ROUTES
    assert {
        entry["route"]["service"]: entry["discovered"]["protocol_evidence"] for entry in services.values()
    } == EXPECTED_PROTOCOL_EVIDENCE

    insufficient = services["http-insufficient"]
    assert insufficient["investigated"] is False
    assert insufficient["validation"]["status"] == "insufficient_evidence"
    assert insufficient["validation"]["candidate"] is False

    assert services["ssh-benign"]["validation"]["status"] == "completed"
    candidate = services["redis-candidate"]["validation"]
    assert candidate["status"] == "completed"
    assert candidate["candidate"] is True
    assert candidate["verified_finding"] is False
    assert candidate["successful_authorized_use"] is False

    remediated = services["redis-remediated"]["validation"]
    assert remediated["status"] == "completed"
    assert remediated["candidate"] is False
    assert remediated["observed_version"] == "redis-lab-7.2-protected"
    assert remediated["dimensions"]["configuration"].endswith("redis-remediated independently identified")

    proof = report["controlled_proof"]
    assert proof["status"] == "completed"
    assert proof["candidate"] is True
    assert proof["verified_finding"] is True
    assert proof["successful_authorized_use"] is True
    assert proof["reproduction_reference"] == "#143"
    assert proof["effect_evidence"]
    assert proof["authorized_use_evidence"]
    assert proof["effect_evidence"] != proof["authorized_use_evidence"]

    assert len(report["approvals"]) == 9
    assert len({receipt["attempt_id"] for receipt in report["approvals"]}) == 9
    assert report["budget"]["charged_attempts"] == 9
    assert report["budget"]["active_concurrency"] == 0
    assert all(item["stopped"] for item in report["cleanup"])
    assert all(item["all_connections_closed"] for item in report["cleanup"])
    assert all(item["response_count"] >= item["connection_count"] for item in report["cleanup"])
    assert all(
        item["request_count"] >= item["connection_count"]
        for item in report["cleanup"]
        if item["case_id"] != "ssh-benign"
    )
    assert next(item for item in report["cleanup"] if item["case_id"] == "redis-candidate")["connection_count"] == 3


def test_lab_registry_covers_seven_families_without_external_claims():
    adapters = lab_service_provider_registry()
    assert {adapter.service: adapter.skill_id for adapter in adapters} == EXPECTED_ROUTES
    assert all(adapter.evidence_scope == "disposable loopback fixture only" for adapter in adapters)
    for skill_id in EXPECTED_ROUTES.values():
        assert (REPOSITORY_ROOT / ".agents" / "skills" / skill_id / "SKILL.md").is_file()
        assert (
            REPOSITORY_ROOT
            / "plugins"
            / "offensive-security"
            / "attack-surface-planner"
            / "skills"
            / skill_id
            / "SKILL.md"
        ).is_file()


@pytest.mark.parametrize(
    ("service", "banner", "expected_response"),
    [
        ("ssh", b"SSH-2.0-Lab_9.0\r\n", b"SSH-2.0-Lab_9.0\r\n"),
        ("smtp", b"220 lab ESMTP\r\n", b"220 lab ESMTP\r\n250-lab\r\n250 HELP\r\n"),
        ("redis", b"", b"+PONG\r\n"),
        ("http", b"HTTP/1.1 200 OK\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"),
    ],
)
def test_fixture_requires_one_use_audit_before_any_response(service, banner, expected_response):
    fixture = _start_fixture(_Case(f"unaudited-{service}", service, banner, "lab-1", candidate=True))
    request = lab._request_for(service, controlled_proof=False)

    def exchange(wire: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", fixture.endpoint.port), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(wire)
            connection.shutdown(socket.SHUT_WR)
            return lab._recv_all(connection)

    def frame(reference: str, correlation: str) -> bytes:
        return f"COPS-AUDIT {reference} {correlation} {len(request)}\n".encode() + request

    try:
        assert exchange(request or b"raw-ssh-request") == b""
        assert exchange(b"COPS-AUDIT malformed\n" + request) == b""
        assert exchange(frame("unknown-reference", "correlation")) == b""
        reference = fixture.server.issue_audit_reference({"dispatch_correlation_id": "correlation"})
        assert exchange(frame(reference, "wrong-correlation")) == b""
        with fixture.server.audit_lock:
            assert fixture.server.requests == []
            assert fixture.server.responses == []
            assert fixture.server.audit == {}
            assert reference in fixture.server.pending_audits

        assert exchange(frame(reference, "correlation")) == expected_response
        completed = fixture.server.read_completed_audit(reference)
        assert completed["closed"] is True
        assert completed["request"] == request
        assert exchange(frame(reference, "correlation")) == b""
        with fixture.server.audit_lock:
            assert fixture.server.pending_audits == {}
            assert fixture.server.audit == {}
            expected_log = [banner, expected_response[len(banner) :]] if service == "smtp" else [expected_response]
            assert fixture.server.responses == expected_log
    finally:
        fixture.stop()


def test_fixture_audit_frame_accepts_fragmented_header_and_request():
    reader, writer = socket.socketpair()

    def send_fragments() -> None:
        try:
            for fragment in (
                b"COPS-AUDIT fixture-ref ",
                b"dispatch-correlation 4\nP",
                b"ING",
            ):
                writer.sendall(fragment)
            writer.shutdown(socket.SHUT_WR)
        finally:
            writer.close()

    thread = threading.Thread(target=send_fragments)
    thread.start()
    try:
        assert _read_wire_request(reader) == ("fixture-ref", "dispatch-correlation", b"PING")
    finally:
        reader.close()
        thread.join(timeout=1)
    assert not thread.is_alive()


def test_fixture_partial_response_write_is_not_published_as_complete():
    class RecordingServer:
        def __init__(self) -> None:
            self.case = _Case("partial-write", "redis", b"", "redis-lab-5.0", candidate=True)
            self.banner = b""
            self.connection_count = 0
            self.requests: list[bytes] = []
            self.responses: list[bytes] = []
            self.audit_lock = threading.Lock()
            self.pending_audits: dict[str, dict[str, object]] = {
                "partial-write-reference": {"dispatch_correlation_id": "partial-write"}
            }
            self.audit: dict[str, dict[str, object]] = {}
            self.closing_audits: dict[object, tuple[str, dict[str, object]]] = {}
            self.worker_failures: list[str] = []

    class PartialWriteConnection:
        def __init__(self, wire: bytes) -> None:
            self._wire = wire
            self.sent = bytearray()

        def settimeout(self, _timeout: float) -> None:
            pass

        def recv(self, size: int) -> bytes:
            chunk = self._wire[:size]
            self._wire = self._wire[size:]
            return chunk

        def sendall(self, data: bytes) -> None:
            self.sent.extend(data[:-2])
            raise OSError("injected partial response write")

    server = RecordingServer()
    audit_reference = "partial-write-reference"
    connection = PartialWriteConnection(f"COPS-AUDIT {audit_reference} partial-write 6\nPING\r\n".encode())
    with pytest.raises(OSError, match="injected partial response write"):
        lab._Handler(connection, ("127.0.0.1", 0), server)

    assert bytes(connection.sent) == b"+PONG"
    with server.audit_lock:
        assert server.requests == [b"PING\r\n"]
        assert server.responses == []
        assert server.worker_failures == ["OSError"]
        assert server.closing_audits == {}
        assert audit_reference not in server.audit


def test_fixture_audit_attests_closure_only_after_transport_is_closed(monkeypatch):
    fixture = _start_fixture(_Case("closure-test", "redis", b"", "redis-lab-5.0", candidate=True))
    entered_shutdown = threading.Event()
    allow_shutdown = threading.Event()
    original_shutdown_request = socketserver.TCPServer.shutdown_request

    def delayed_shutdown_request(server: socketserver.TCPServer, request: socket.socket) -> None:
        entered_shutdown.set()
        if not allow_shutdown.wait(timeout=5):
            raise RuntimeError("test did not release fixture shutdown")
        original_shutdown_request(server, request)

    monkeypatch.setattr(socketserver.TCPServer, "shutdown_request", delayed_shutdown_request)
    audit_reference = fixture.server.issue_audit_reference({"dispatch_correlation_id": "closure-test"})
    audit_result: list[dict[str, object]] = []
    audit_errors: list[Exception] = []
    audit_finished = threading.Event()

    def read_completed_audit() -> None:
        try:
            audit_result.append(lab._Verifier(fixture)._read_audit(audit_reference))
        except Exception as exc:
            audit_errors.append(exc)
        finally:
            audit_finished.set()

    try:
        with socket.create_connection(("127.0.0.1", fixture.endpoint.port), timeout=2) as connection:
            connection.sendall(f"COPS-AUDIT {audit_reference} closure-test 6\nPING\r\n".encode())
            assert connection.recv(128) == b"+PONG\r\n"
            assert entered_shutdown.wait(timeout=2)
            reader = threading.Thread(target=read_completed_audit)
            reader.start()
            assert not audit_finished.wait(timeout=0.6)
            with fixture.server.audit_lock:
                assert audit_reference not in fixture.server.audit
                assert fixture.server.closed_connections == 0
            allow_shutdown.set()
            assert audit_finished.wait(timeout=2)
            reader.join(timeout=1)
            assert not reader.is_alive()
            assert audit_errors == []
            assert len(audit_result) == 1
            assert audit_result[0]["closed"] is True
            with fixture.server.audit_lock:
                assert fixture.server.closed_connections == 1
    finally:
        allow_shutdown.set()
        fixture.stop()


def test_fixture_stop_rejects_live_request_worker(monkeypatch):
    entered_handler = threading.Event()
    release_handler = threading.Event()
    original_response = lab._fixture_response

    def blocked_response(case: _Case, request: bytes) -> bytes:
        if case.case_id == "blocked-handler":
            entered_handler.set()
            if not release_handler.wait(timeout=5):
                raise RuntimeError("test did not release fixture handler")
        return original_response(case, request)

    monkeypatch.setattr(lab, "_fixture_response", blocked_response)
    fixture = _start_fixture(_Case("blocked-handler", "redis", b"", "redis-lab-5.0", candidate=True))
    connection = socket.create_connection(("127.0.0.1", fixture.endpoint.port), timeout=2)
    try:
        reference = fixture.server.issue_audit_reference({"dispatch_correlation_id": "blocked-handler"})
        connection.sendall(f"COPS-AUDIT {reference} blocked-handler 6\nPING\r\n".encode())
        assert entered_handler.wait(timeout=2)
        with pytest.raises(RuntimeError, match="did not stop cleanly"):
            fixture.stop()
        with fixture.server.audit_lock:
            assert fixture.server.active_requests
    finally:
        release_handler.set()
        connection.close()
    for _ in range(100):
        with fixture.server.audit_lock:
            if not fixture.server.active_requests:
                break
        time.sleep(0.01)
    with fixture.server.audit_lock:
        assert not fixture.server.active_requests


def test_fixture_stop_reports_worker_transport_close_failure(monkeypatch):
    fixture = _start_fixture(_Case("close-failure", "redis", b"", "redis-lab-5.0", candidate=True))
    original_shutdown_request = socketserver.TCPServer.shutdown_request
    close_attempted = threading.Event()

    def failed_shutdown_request(server: socketserver.TCPServer, request: socket.socket) -> None:
        if server is fixture.server:
            close_attempted.set()
            raise OSError("injected transport close failure")
        original_shutdown_request(server, request)

    monkeypatch.setattr(socketserver.TCPServer, "shutdown_request", failed_shutdown_request)
    audit_reference = fixture.server.issue_audit_reference({"dispatch_correlation_id": "close-failure"})
    with socket.create_connection(("127.0.0.1", fixture.endpoint.port), timeout=2) as connection:
        connection.sendall(f"COPS-AUDIT {audit_reference} close-failure 6\nPING\r\n".encode())
        assert connection.recv(128) == b"+PONG\r\n"
        assert close_attempted.wait(timeout=2)
    with pytest.raises(RuntimeError, match="did not stop cleanly"):
        fixture.stop()
    with fixture.server.audit_lock:
        assert fixture.server.worker_failures == ["OSError"]
        assert audit_reference not in fixture.server.audit


def test_public_subprocess_runs_complete_service_validation_journey(tmp_path):
    assert_complete_public_journey(run_public_journey(tmp_path / "state"))


def test_public_subprocess_default_resolves_symlinked_temporary_root(tmp_path):
    real_temporary_root = tmp_path / "real-temporary-root"
    real_temporary_root.mkdir()
    temporary_root_alias = tmp_path / "temporary-root-alias"
    temporary_root_alias.symlink_to(real_temporary_root, target_is_directory=True)

    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=REPOSITORY_ROOT,
        env={**os.environ, "TMPDIR": str(temporary_root_alias)},
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert_complete_public_journey(json.loads(completed.stdout))


def test_public_subprocess_rejects_reused_state_directory(tmp_path):
    state_directory = tmp_path / "state"
    run_public_journey(state_directory)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--state-dir", str(state_directory)],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "state directory must be a fresh path beneath real directories" in completed.stderr


def test_journey_rejects_existing_state_directory_before_starting_fixtures(tmp_path, monkeypatch):
    state_directory = tmp_path / "state"
    state_directory.mkdir()

    monkeypatch.setattr(lab, "_start_fixture", lambda _case: pytest.fail("fixture started before state claim"))

    with pytest.raises(ValueError, match="state directory must be a fresh path"):
        lab.run_loopback_service_validation_journey(state_directory)


def test_journey_rejects_symlink_ancestor_before_starting_fixtures(tmp_path, monkeypatch):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)

    monkeypatch.setattr(lab, "_start_fixture", lambda _case: pytest.fail("fixture started before state claim"))

    with pytest.raises(ValueError, match="state directory must be a fresh path"):
        lab.run_loopback_service_validation_journey(alias / "state")
    assert not (real_parent / "state").exists()


def test_journey_allows_only_one_concurrent_state_directory_claim(tmp_path, monkeypatch):
    state_directory = tmp_path / "state"
    first_claimed = threading.Event()
    release_first = threading.Event()
    first_error: list[BaseException] = []

    def hold_after_claim(_case):
        first_claimed.set()
        if not release_first.wait(timeout=5):
            raise RuntimeError("timed out waiting to release claimed state directory")
        raise RuntimeError("stop after exclusive state directory claim")

    def run_first_claim() -> None:
        try:
            lab.run_loopback_service_validation_journey(state_directory)
        except BaseException as exc:
            first_error.append(exc)

    monkeypatch.setattr(lab, "_start_fixture", hold_after_claim)
    first = threading.Thread(target=run_first_claim)
    first.start()
    try:
        assert first_claimed.wait(timeout=5)
        with pytest.raises(ValueError, match="state directory must be a fresh path"):
            lab.run_loopback_service_validation_journey(state_directory)
    finally:
        release_first.set()
        first.join(timeout=5)

    assert not first.is_alive()
    assert len(first_error) == 1
    assert isinstance(first_error[0], RuntimeError)
    assert str(first_error[0]) == "stop after exclusive state directory claim"


def test_journey_rejects_state_directory_replacement_at_ledger_open(tmp_path, monkeypatch):
    state_directory = tmp_path / "state"
    displaced_directory = tmp_path / "displaced"
    monkeypatch.setattr(lab, "_CASES", ())

    def replace_claimed_directory(_session, *, approved_endpoints):
        assert approved_endpoints == set()
        state_directory.rename(displaced_directory)
        state_directory.mkdir(mode=0o700)
        return []

    monkeypatch.setattr(lab, "prepare_session_service_handoffs", replace_claimed_directory)

    with pytest.raises(RuntimeError, match="budget directory identity changed"):
        lab.run_loopback_service_validation_journey(state_directory)
    assert not (state_directory / "service-validation.sqlite3").exists()
    assert not (displaced_directory / "service-validation.sqlite3").exists()


def test_ledger_rejects_state_directory_replacement_after_initialization(tmp_path):
    state_directory = tmp_path / "state"
    displaced_directory = tmp_path / "displaced"
    state_fd = lab.create_directory_exclusive_no_symlinks(state_directory, mode=0o700)
    try:
        ledger = lab._ledger(state_directory, directory_fd=state_fd)
        state_directory.rename(displaced_directory)
        state_directory.mkdir(mode=0o700)

        with pytest.raises(RuntimeError, match="budget directory identity changed"):
            ledger.snapshot()

        assert not (state_directory / "service-validation.sqlite3").exists()
        assert (displaced_directory / "service-validation.sqlite3").is_file()
    finally:
        os.close(state_fd)


def test_cleanup_failure_attempts_every_fixture_and_fails_closed(tmp_path, monkeypatch):
    started: list[lab._RunningFixture] = []
    stopped: list[str] = []
    original_start = lab._start_fixture
    original_stop = lab._RunningFixture.stop

    def capture_start(case: lab._Case) -> lab._RunningFixture:
        fixture = original_start(case)
        started.append(fixture)
        return fixture

    def fault_after_stop(fixture: lab._RunningFixture) -> None:
        original_stop(fixture)
        stopped.append(fixture.case.case_id)
        if fixture.case.case_id == "http-insufficient":
            raise RuntimeError("injected cleanup failure")

    monkeypatch.setattr(lab, "_start_fixture", capture_start)
    monkeypatch.setattr(lab._RunningFixture, "stop", fault_after_stop)
    with pytest.raises(RuntimeError, match="fixture cleanup failed: http-insufficient"):
        lab.run_loopback_service_validation_journey(tmp_path / "state")
    assert len(started) == len(lab._CASES)
    assert len(stopped) == len(lab._CASES)
    assert all(not fixture.thread.is_alive() for fixture in started)


def test_cleanup_failure_preserves_primary_journey_failure(tmp_path, monkeypatch):
    original_start = lab._start_fixture
    original_stop = lab._RunningFixture.stop
    started: list[lab._RunningFixture] = []

    def fail_after_first_start(case: lab._Case) -> lab._RunningFixture:
        if started:
            raise ValueError("injected journey failure")
        fixture = original_start(case)
        started.append(fixture)
        return fixture

    def fail_after_stop(fixture: lab._RunningFixture) -> None:
        original_stop(fixture)
        raise RuntimeError("injected cleanup failure")

    monkeypatch.setattr(lab, "_start_fixture", fail_after_first_start)
    monkeypatch.setattr(lab._RunningFixture, "stop", fail_after_stop)
    with pytest.raises(ValueError, match="injected journey failure") as captured:
        lab.run_loopback_service_validation_journey(tmp_path / "state")
    assert len(started) == 1
    assert not started[0].thread.is_alive()
    assert "fixture cleanup failed: http-insufficient" in captured.value.__notes__
