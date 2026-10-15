from __future__ import annotations

import json
import hashlib
import shutil
from pathlib import Path
from typing import Literal, cast

import pytest

from cops.laboratory.service_lab import (
    FIXTURE_DIRECTORY,
    ServiceLaboratory,
    probe_isolated_runtime,
    verify_fixture_manifest,
)


def test_fixture_manifest_verifies_and_detects_tampering(tmp_path: Path) -> None:
    assert len(verify_fixture_manifest()) == 64
    copied = tmp_path / "fixtures"
    shutil.copytree(FIXTURE_DIRECTORY, copied)
    with (copied / "entra-grants.jsonl").open("a", encoding="utf-8") as stream:
        stream.write("{}\n")
    with pytest.raises(ValueError, match="fixture checksum mismatch"):
        verify_fixture_manifest(copied)


def test_offline_playback_executes_rules_against_attack_and_benign_events() -> None:
    report = ServiceLaboratory().run_offline_playback()

    assert report.path == "offline-playback"
    assert report.service_activity == {"fixtures_read": 4, "events_evaluated": 8}
    assert report.detection_counts["class:attack"] == 4
    assert report.detection_counts["class:benign"] == 4
    assert len(report.alert_events) == 4
    assert len(report.telemetry_events) == 8
    assert all(event["correlation_id"] and event["timestamp"].endswith("Z") for event in report.telemetry_events)
    assert all(alert["alert"] is True and alert["timestamp"].endswith("Z") for alert in report.alert_events)
    assert "not EVTX" in report.limitations[0]


@pytest.mark.parametrize(
    ("profile", "lateral_status", "reached", "lateral_rule"),
    [
        ("vulnerable", 200, True, "rule:lateral-movement"),
        ("corrected", 403, False, "rule:lateral-movement-blocked"),
    ],
)
def test_process_acceptance_proves_actual_activity_and_reset(
    tmp_path: Path,
    profile: Literal["vulnerable", "corrected"],
    lateral_status: int,
    reached: bool,
    lateral_rule: str,
) -> None:
    report = ServiceLaboratory().run_process_acceptance(profile, telemetry_directory=tmp_path / profile)

    activity = report.service_activity
    assert activity["identity_issue_status"] == 201
    assert activity["authenticated_status"] == 200
    assert activity["lateral_status"] == lateral_status
    assert activity["lateral_target_reached"] is reached
    assert activity["profile_configuration_verified"] is True
    assert activity["ioc_ingest_status"] == 201
    assert activity["hunt_status"] == 200
    assert activity["hunt_hit"] is True
    assert activity["containment_status"] == 200
    assert activity["post_revoke_authenticated_status"] == 401
    assert activity["actual_tcp_services"] == 4
    assert activity["loopback_bind_verified"] is True
    assert activity["graph_was_dirty_before_final_reset"] is True
    assert report.detection_counts[lateral_rule] == 1
    assert report.detection_counts["rule:credential-revocation"] == 1
    assert report.detection_counts["rule:post-revocation-auth-failure"] == 1
    assert report.detection_counts["rule:ioc-hunt-hit"] == 1
    assert report.detection_counts["rule:ioc-containment"] == 1
    assert report.tls == {
        "valid_client_status": 204,
        "missing_client_rejected": True,
        "untrusted_client_rejected": True,
        "untrusted_server_rejected": True,
        "server_address": "127.0.0.1",
        "protocol": "TLS",
    }
    expected_verdict = "fail" if profile == "vulnerable" else "pass"
    assert activity["api"]["authorization_verdict"] == expected_verdict
    assert activity["api"]["rate_limit_verdict"] == expected_verdict
    assert activity["api"]["actual_requests"] == 10
    assert activity["api"]["reset_verified"] is True
    assert activity["api"]["service_stopped"] is True
    assert activity["jwt"]["actual_requests"] == 9
    assert activity["jwt"]["statuses"]["valid"] == 204
    assert all(status == 401 for name, status in activity["jwt"]["statuses"].items() if name != "valid")
    assert activity["jwt"]["service_stopped"] is True
    boundaries = activity["boundaries"]
    assert boundaries["benign_query_preserved"] is True
    assert boundaries["injection_exposed_other_object"] is reached
    assert boundaries["injection_rows"] == (2 if reached else 0)
    assert boundaries["allowed_tool_status"] == 200
    assert boundaries["denied_attack_calls"] == (0 if reached else 4)
    assert bool(boundaries["application_codes"]) is reached
    assert set(boundaries["gateway_codes"]) == ({"foundry_tool_scope", "foundry_resource_scope", "foundry_prompt_injection"} if reached else set())
    assert boundaries["actual_requests"] == 7
    assert boundaries["service_stopped"] is True
    acquisition = activity["acquisition"]
    assert all(acquisition[field] for field in ("original_unchanged", "permission_rejected", "modified_source_rejected", "no_partial_outputs", "disposable_root_removed"))
    assert acquisition["finding_codes"] == []
    assert report.restoration == {
        "success": True,
        "failure": True,
        "cancellation": True,
        "final_graph_reset": True,
    }
    assert report.isolation.verified is False
    assert report.isolation.blocker
    assert all(event["correlation_id"] == report.run_id for event in report.telemetry_events)
    assert all(alert["correlation_id"] == report.run_id for alert in report.alert_events)
    persisted = [json.loads(line) for line in (tmp_path / profile / "telemetry.jsonl").read_text().splitlines()]
    assert persisted == list(report.telemetry_events)


def test_sysmon_json_is_not_represented_as_evtx() -> None:
    manifest = json.loads((FIXTURE_DIRECTORY / "manifest.json").read_text(encoding="utf-8"))
    sysmon = next(item for item in manifest["fixtures"] if item["path"] == "sysmon-normalized.jsonl")
    assert sysmon["is_evtx"] is False
    events = [json.loads(line) for line in (FIXTURE_DIRECTORY / sysmon["path"]).read_text().splitlines()]
    assert all(event["provenance"]["source_format"] == "normalized-sysmon-json" for event in events)
    assert all(event["provenance"]["acquisition_adapter"].startswith("unsupported") for event in events)


def test_runtime_probe_never_treats_availability_as_verified_isolation() -> None:
    probe = probe_isolated_runtime()
    assert probe.verified is False
    assert probe.blocker


def test_process_acceptance_rejects_unknown_profile_before_path_resolution() -> None:
    unknown = cast(Literal["vulnerable", "corrected"], "../outside")
    with pytest.raises(ValueError, match="unsupported service profile"):
        ServiceLaboratory().run_process_acceptance(unknown)


def _rewrite_fixture(directory: Path, name: str, events: list[dict]) -> None:
    raw = "".join(json.dumps(event) + "\n" for event in events).encode()
    (directory / name).write_bytes(raw)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    next(item for item in manifest["fixtures"] if item["path"] == name)["sha256"] = hashlib.sha256(raw).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


def test_offline_rules_use_event_fields_instead_of_fixture_risk_labels(tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(FIXTURE_DIRECTORY, fixtures)
    for path in fixtures.glob("*.jsonl"):
        events = [json.loads(line) for line in path.read_text().splitlines()]
        for event in events:
            event["risk"] = "benign" if event["risk"] == "attack" else "attack"
        _rewrite_fixture(fixtures, path.name, events)
    report = ServiceLaboratory(fixtures).run_offline_playback()
    assert len(report.alert_events) == 4
    assert len([name for name in report.detection_counts if name.startswith("rule:")]) == 4


def test_consent_correlation_requires_the_observed_dangerous_permission(tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(FIXTURE_DIRECTORY, fixtures)
    events = [json.loads(line) for line in (fixtures / "entra-grants.jsonl").read_text().splitlines()]
    for event in events:
        event["permission"] = "User.Read"
    _rewrite_fixture(fixtures, "entra-grants.jsonl", events)
    report = ServiceLaboratory(fixtures).run_offline_playback()
    assert len(report.alert_events) == 2
    assert all("entra" not in alert["rule_id"] for alert in report.alert_events)


@pytest.mark.parametrize("mutation", ["traversal", "duplicate", "symlink", "oversized"])
def test_fixture_manifest_rejects_unbounded_or_untrusted_paths(tmp_path: Path, mutation: str) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(FIXTURE_DIRECTORY, fixtures)
    path = fixtures / "manifest.json"
    manifest = json.loads(path.read_text())
    if mutation == "traversal":
        manifest["fixtures"][0]["path"] = "../outside.json"
    elif mutation == "duplicate":
        manifest["fixtures"][1]["path"] = manifest["fixtures"][0]["path"]
    elif mutation == "symlink":
        target = fixtures / manifest["fixtures"][0]["path"]
        target.unlink()
        target.symlink_to(FIXTURE_DIRECTORY / manifest["fixtures"][0]["path"])
    else:
        path.write_bytes(b" " * (1024 * 1024 + 1))
    if mutation != "oversized":
        path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        verify_fixture_manifest(fixtures)
