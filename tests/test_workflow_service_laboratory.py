from __future__ import annotations

import json
from pathlib import Path

import pytest

from cops.laboratory import workflow_lab
from cops.laboratory.service_lab import IsolationProbe


def _events(report: workflow_lab.WorkflowServiceLaboratoryReport, event: str) -> list[dict[str, object]]:
    return [record for record in report.telemetry_events if record.get("event") == event]


def test_success_runs_authorized_tcp_workflow_and_revocation(tmp_path: Path) -> None:
    report = workflow_lab.run_workflow_service_laboratory(tmp_path / "success", run_id="workflow-success")

    assert report.status == "success"
    assert report.workflow["outputs"] == {"contained": True, "post_revoke_status": 401}
    assert report.authorization["provisioned"] == 3
    assert report.authorization["consumed"] == 3
    assert report.authorization["one_use_store"] is True
    assert report.service_activity["actual_tcp_services"] == 4
    assert [(request["stage"], request["status"]) for request in report.service_activity["requests"]] == [
        ("setup", 201),
        ("ingest", 201),
        ("hunt", 200),
        ("contain", 200),
        ("contain", 401),
    ]
    assert report.detection_counts == {
        "class:attack": 5,
        "class:benign": 1,
        "rule:credential-revocation": 1,
        "rule:post-revocation-auth-failure": 1,
        "rule:ioc-hunt-hit": 1,
        "rule:ioc-containment": 1,
    }
    assert _events(report, "credential_revoked")
    assert _events(report, "authenticated_access_rejected")
    assert all(event["correlation_id"] == report.run_id for event in report.telemetry_events)
    assert all(alert["alert"] is True for alert in report.alert_events)
    assert report.restoration == {
        "cleanup_invoked": False,
        "baseline_before_graph_exit": False,
        "baseline_restored": True,
        "services_stopped": True,
    }


def test_failure_invokes_stage_cleanup_and_restores_baseline(tmp_path: Path) -> None:
    report = workflow_lab.run_workflow_service_laboratory(tmp_path / "failure", mode="failure")

    assert report.status == "partial_failure"
    assert report.authorization["consumed"] == 2
    assert [request["stage"] for request in report.service_activity["requests"]] == ["setup", "ingest", "hunt"]
    assert report.restoration == {
        "cleanup_invoked": True,
        "baseline_before_graph_exit": True,
        "baseline_restored": True,
        "services_stopped": True,
    }


def test_cancellation_stops_before_hunt_and_context_restores(tmp_path: Path) -> None:
    report = workflow_lab.run_workflow_service_laboratory(tmp_path / "cancel", mode="cancellation")

    assert report.status == "cancelled"
    assert report.authorization["consumed"] == 1
    assert [request["stage"] for request in report.service_activity["requests"]] == ["setup", "ingest"]
    assert report.restoration == {
        "cleanup_invoked": False,
        "baseline_before_graph_exit": False,
        "baseline_restored": True,
        "services_stopped": True,
    }


def test_require_isolation_blocks_before_state_creation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state_dir = tmp_path / "must-not-exist"
    probe = IsolationProbe(
        verified=False,
        mechanism="loopback-only",
        evidence=("no container or network namespace proof",),
        blocker="verified network isolation is unavailable",
    )
    monkeypatch.setattr(workflow_lab, "probe_isolated_runtime", lambda: probe)

    with pytest.raises(workflow_lab.IsolationRequiredError, match="verified network isolation is unavailable"):
        workflow_lab.run_workflow_service_laboratory(state_dir, require_isolation=True)

    assert not state_dir.exists()


def test_synthetic_credential_is_not_persisted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sentinel = "synthetic-credential-must-not-persist"
    state_dir = tmp_path / "secret-check"
    monkeypatch.setattr(workflow_lab.secrets, "token_urlsafe", lambda _size: sentinel)

    report = workflow_lab.run_workflow_service_laboratory(state_dir)

    assert sentinel not in json.dumps(report.to_dict(), sort_keys=True)
    for path in state_dir.rglob("*"):
        if path.is_file():
            assert sentinel.encode() not in path.read_bytes(), path
