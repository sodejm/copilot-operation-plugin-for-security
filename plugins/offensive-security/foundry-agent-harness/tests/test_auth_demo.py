"""The operator authorization demonstration is runnable and self-verifying."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def test_operator_demo_runs_complete_authorization_matrix(tmp_path):
    report_path = tmp_path / "auth-demo-report.json"
    result = subprocess.run(
        [
            sys.executable,
            str(PLUGIN_ROOT / "scripts/run_auth_demo.py"),
            "--output",
            str(report_path),
        ],
        cwd=PLUGIN_ROOT.parents[2],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    payload = report_path.read_bytes()
    assert summary["schema_version"] == "cops.agent-mcp-auth-demo-summary/v1"
    assert summary["status"] == "passed"
    assert summary["case_count"] == 22
    assert summary["report"] == str(report_path.resolve())
    assert summary["report_bytes"] == len(payload)
    assert summary["report_sha256"] == hashlib.sha256(payload).hexdigest()
    assert summary["approval_private_directory_removed"] is True
    assert "same host and trust boundary" in summary["observer_boundary"]
    assert summary["public_cli"] == {
        "auth_plan_exit_code": 0,
        "auth_lab_exit_code": 0,
        "replayed_auth_lab_exit_code": 2,
        "same_approval_replay_denied": True,
        "replay_denial_reason": "already_consumed_or_revoked",
    }
    assert summary["declared_limitations"] == [
        "no_native_provider_authority",
        "no_independently_authenticated_external_observer",
        "no_windows_runtime_acceptance",
        "no_os_enforced_egress_containment",
        "no_durable_host_loss_recovery",
    ]
    if os.name == "posix":
        assert report_path.stat().st_mode & 0o777 == 0o600

    report = json.loads(payload)
    assert report["planned_case_count"] == report["completed_case_count"] == 22
    assert report["pending_case_ids"] == []
    assert report["recovery_actions"] == []
    assert report["all_expectations_met"] is report["security_pass"] is True
    assert report["source_snapshot"] == {
        "verified": True,
        "private_directory_removed": True,
        "reason": None,
        "failures": [],
    }
    assert all(row["outcome"] == "pass" for row in report["results"])
    assert all(
        row["cleanup"] == {"process_exit_observed": True, "private_directory_removed": True}
        for row in report["results"]
    )
    assert sum(len(row["observed_effects"]) for row in report["results"]) == 8
