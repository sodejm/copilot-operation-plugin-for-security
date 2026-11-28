"""End-to-end checks for the packaged telemetry proof playback."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
RUNNER = PLUGIN_ROOT / "scripts" / "run_demo.py"


def test_playback_writes_healthy_degraded_and_broken_reports(tmp_path: Path) -> None:
    out_dir = tmp_path / "telemetry-output"
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "--out-dir", str(out_dir)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads((out_dir / "playback-summary.json").read_text(encoding="utf-8"))
    health = {item["scenario"]: item["actual_health"] for item in summary["scenarios"]}
    assert summary["schema_version"] == "cops.telemetry-proof-playback/v1"
    assert summary["status"] == "passed"
    assert summary["rerun_equivalent"] is True
    assert health == {
        "cribl-splunk-route": "healthy",
        "cribl-sentinel-route": "healthy",
        "hec-indexed-rule-missed": "degraded",
        "missing-cribl-stage": "broken",
        "cross-tenant-collision": "broken",
    }
    for item in summary["scenarios"]:
        report = json.loads((out_dir / item["json_report"]).read_text(encoding="utf-8"))
        assert report["schema_version"] == "cops.proof-report/v1"
        assert (out_dir / item["markdown_report"]).is_file()


def test_playback_fails_when_a_required_manifest_is_missing(tmp_path: Path) -> None:
    fixtures_root = tmp_path / "fixtures"
    fixtures_root.mkdir()
    out_dir = tmp_path / "telemetry-output"
    completed = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--fixtures-root",
            str(fixtures_root),
            "--out-dir",
            str(out_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "Missing required manifest" in completed.stderr
    assert not (out_dir / "playback-summary.json").exists()
