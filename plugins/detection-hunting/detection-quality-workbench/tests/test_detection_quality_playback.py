"""End-to-end checks for the packaged detection-quality playback."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
RUNNER = PLUGIN_ROOT / "scripts" / "run_demo.py"


def test_playback_writes_rule_reports_and_schema_failures(tmp_path: Path) -> None:
    out_dir = tmp_path / "quality-output"
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "--out-dir", str(out_dir)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads((out_dir / "playback-summary.json").read_text(encoding="utf-8"))
    assert summary["schema_version"] == "cops.detection-quality-playback/v1"
    assert summary["status"] == "passed"
    assert summary["rerun_equivalent"] is True
    assert {item["platform"] for item in summary["rules"]} == {"sentinel_kql", "splunk_spl"}

    for item in summary["rules"]:
        metrics = item["metrics"]
        assert metrics["true_positives"] > 0
        assert metrics["true_negatives"] > 0
        assert metrics["schema_error_cases"] > 0
        assert metrics["false_positives"] == 0
        assert metrics["false_negatives"] == 0
        report = json.loads((out_dir / item["json_report"]).read_text(encoding="utf-8"))
        assert report["schema_version"] == "cops.detection-quality-report/v2"
        assert any(case["outcome_classification"] == "missing_field_error" for case in report["case_results"])
        assert (out_dir / item["markdown_report"]).is_file()


def test_playback_fails_when_fixtures_are_missing_or_empty(tmp_path: Path) -> None:
    out_dir = tmp_path / "quality-output"
    missing = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--fixtures-dir",
            str(tmp_path / "missing"),
            "--out-dir",
            str(out_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert missing.returncode == 2
    assert "Fixtures directory not found" in missing.stderr

    empty = tmp_path / "empty"
    empty.mkdir()
    empty_run = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--rules-dir",
            str(empty),
            "--fixtures-dir",
            str(empty),
            "--out-dir",
            str(out_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert empty_run.returncode == 2
    assert "No rule definitions found" in empty_run.stderr
    assert not (out_dir / "playback-summary.json").exists()
