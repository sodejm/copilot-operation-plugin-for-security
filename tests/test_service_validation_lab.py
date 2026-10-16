from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

from cops.discovery import lab_service_provider_registry
from cops.discovery.service_validation_lab import _read_wire_request

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


def test_public_subprocess_runs_complete_service_validation_journey(tmp_path):
    assert_complete_public_journey(run_public_journey(tmp_path / "state"))
