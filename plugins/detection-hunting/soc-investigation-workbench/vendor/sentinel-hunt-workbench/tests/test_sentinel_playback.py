"""End-to-end checks for the packaged Sentinel playback."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
RUNNER = PLUGIN_ROOT / "scripts" / "run_demo.py"
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from scripts.run_demo import _evaluate  # noqa: E402


def test_playback_writes_full_artifact_chain(tmp_path: Path) -> None:
    out_dir = tmp_path / "sentinel-output"
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "--out-dir", str(out_dir)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads((out_dir / "playback-summary.json").read_text(encoding="utf-8"))
    evaluation = json.loads((out_dir / "evaluation-summary.json").read_text(encoding="utf-8"))
    qualification = json.loads((out_dir / "qualification-report.json").read_text(encoding="utf-8"))

    assert summary["schema_version"] == "huntwb.playback-summary/v1"
    assert summary["status"] == "passed"
    assert summary["rendered_artifact_count"] == 12
    assert summary["rerun_equivalent"] is True
    for artifact in summary["rendered_artifacts"]:
        rendered = json.loads((out_dir / artifact["path"]).read_text(encoding="utf-8"))
        assert rendered["artifact_schema"] == "huntwb.rendered-hunt/v1"
        assert rendered["surface"]["id"] == "sentinel_analytics"

    assert evaluation["status"] == "passed"
    assert set(evaluation["hunts"]) == {"H01", "H02", "H10"}
    for outcomes in evaluation["hunts"].values():
        assert outcomes["malicious"]["actual_outcome"] == "match"
        assert outcomes["benign"]["actual_outcome"] == "no_escalation"
        assert outcomes["insufficient"]["expected_outcome"] == "insufficient_evidence"
        assert outcomes["insufficient"]["actual_outcome"] == "insufficient_evidence"
        assert outcomes["insufficient"]["fixture_expected_qualification_outcome"] == "validation_failure"
        assert outcomes["insufficient"]["reason"] == "modeled_static_validation_failure"
        assert all(outcome["passed"] for outcome in outcomes.values())

    assert qualification["status"] == "passed"
    assert qualification["semantic_mutations"] > 0
    assert qualification["semantic_mutations_caught"] == qualification["semantic_mutations"]


def test_playback_fails_when_curated_fixtures_are_missing(tmp_path: Path) -> None:
    out_dir = tmp_path / "sentinel-output"
    completed = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--fixtures-root",
            str(tmp_path / "missing"),
            "--out-dir",
            str(out_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "[ERROR]" in completed.stderr
    assert not (out_dir / "playback-summary.json").exists()


def test_expected_validation_failure_cannot_relabel_valid_input(tmp_path: Path) -> None:
    source = json.loads((PLUGIN_ROOT / "fixtures" / "curated" / "H01.json").read_text(encoding="utf-8"))
    positive = next(scenario for scenario in source["scenarios"] if scenario["category"] == "true_positive")
    schema = next(scenario for scenario in source["scenarios"] if scenario["category"] == "schema_surface")
    schema["input"] = positive["input"]
    schema["expected_qualification_outcome"] = "validation_failure"
    (tmp_path / "H01.json").write_text(json.dumps(source), encoding="utf-8")

    outcome = _evaluate("H01", tmp_path)["insufficient"]

    assert outcome["fixture_expected_qualification_outcome"] == "validation_failure"
    assert outcome["actual_outcome"] == "match"
    assert outcome["reason"] == "reference_invariants_satisfied"
    assert outcome["passed"] is False
