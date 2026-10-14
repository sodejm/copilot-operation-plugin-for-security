#!/usr/bin/env python3
"""Run the complete offline Telemetry Proof Pack playback."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from proofpack.cli import load_evidence_files  # noqa: E402
from proofpack.correlator import correlate_pipeline_evidence  # noqa: E402
from proofpack.models import ProofError, RunManifest  # noqa: E402
from proofpack.reporting import render_json_report, render_markdown_report  # noqa: E402

SCENARIOS = {
    "cribl-splunk-route": ("routes/cribl-splunk-route", "healthy"),
    "cribl-sentinel-route": ("routes/cribl-sentinel-route", "healthy"),
    "hec-indexed-rule-missed": ("failures/hec-indexed-rule-missed", "degraded"),
    "missing-cribl-stage": ("failures/missing-cribl-stage", "broken"),
    "cross-tenant-collision": ("failures/cross-tenant-collision", "broken"),
}


def _assert_json_artifact(path: Path, schema_value: str) -> dict[str, object]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ProofError(f"Missing or empty playback artifact: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != schema_value:
        raise ProofError(f"Unexpected schema in playback artifact: {path}")
    return payload


def _assert_markdown_artifact(path: Path) -> None:
    if not path.is_file() or not path.read_text(encoding="utf-8").strip():
        raise ProofError(f"Missing or empty playback artifact: {path}")


def _stable_report(report: dict[str, object]) -> dict[str, object]:
    """Return fields derived from evidence, excluding the wall-clock evaluation time."""
    return {key: value for key, value in report.items() if key != "evaluated_at"}


@contextmanager
def output_directory(requested: Path | None) -> Iterator[tuple[Path, bool]]:
    if requested is not None:
        requested.mkdir(parents=True, exist_ok=True)
        os.chmod(requested, 0o700)
        yield requested, True
        return
    with tempfile.TemporaryDirectory(prefix="telemetry-proof-playback-") as raw:
        path = Path(raw)
        os.chmod(path, 0o700)
        yield path, False


def _evaluate_scenario(fixtures_root: Path, relative: str) -> dict[str, object]:
    directory = fixtures_root / relative
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        raise ProofError(f"Missing required manifest: {manifest_path}")
    manifest = RunManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
    evidence = load_evidence_files(directory)
    if not evidence:
        raise ProofError(f"No evidence files found: {directory}")
    return correlate_pipeline_evidence(manifest, evidence)


def run_playback(fixtures_root: Path, out_dir: Path) -> dict[str, object]:
    reports: dict[str, dict[str, object]] = {}
    scenario_results: list[dict[str, object]] = []
    for name, (relative, expected_health) in SCENARIOS.items():
        report = _evaluate_scenario(fixtures_root, relative)
        actual_health = report["pipeline_health"]
        if actual_health != expected_health:
            raise ProofError(f"{name}: expected {expected_health}, got {actual_health}")
        reports[name] = report
        scenario_dir = out_dir / "scenarios" / name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        (scenario_dir / "report.json").write_text(render_json_report(report), encoding="utf-8")
        (scenario_dir / "report.md").write_text(render_markdown_report(report), encoding="utf-8")
        written = _assert_json_artifact(scenario_dir / "report.json", "cops.proof-report/v1")
        _assert_markdown_artifact(scenario_dir / "report.md")
        if written.get("pipeline_health") != expected_health:
            raise ProofError(f"{name}: written report health assertion failed")
        scenario_results.append(
            {
                "scenario": name,
                "expected_health": expected_health,
                "actual_health": actual_health,
                "observed_stages": report["summary"]["observed_stages_count"],
                "json_report": f"scenarios/{name}/report.json",
                "markdown_report": f"scenarios/{name}/report.md",
                "passed": True,
            }
        )

    rerun = {name: _evaluate_scenario(fixtures_root, relative) for name, (relative, _) in SCENARIOS.items()}
    if {name: _stable_report(report) for name, report in rerun.items()} != {
        name: _stable_report(report) for name, report in reports.items()
    }:
        raise ProofError("playback rerun produced different correlation reports")

    summary = {
        "schema_version": "cops.telemetry-proof-playback/v1",
        "status": "passed",
        "scenarios": scenario_results,
        "rerun_equivalent": True,
        "evidence_scope": "supplied_offline_fixture_records_only",
        "evidence_limitations": [
            "No Cribl, Splunk, Sentinel, or other provider API was queried.",
            "Pipeline health classifies the supplied records and does not establish production uptime.",
        ],
    }
    (out_dir / "playback-summary.json").write_text(render_json_report(summary), encoding="utf-8")
    written_summary = _assert_json_artifact(out_dir / "playback-summary.json", "cops.telemetry-proof-playback/v1")
    if written_summary.get("status") != "passed":
        raise ProofError("Written playback summary did not pass validation")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures-root", type=Path, default=PLUGIN_ROOT / "fixtures")
    parser.add_argument("--out-dir", type=Path, help="Retain artifacts in this private directory")
    args = parser.parse_args(argv)
    try:
        with output_directory(args.out_dir) as (out_dir, retained):
            summary = run_playback(args.fixtures_root, out_dir)
            print(json.dumps(summary, indent=2))
            location = f"retained at {out_dir}" if retained else "validated in a disposable directory"
            print(f"[OK] artifacts {location}")
        return 0
    except (OSError, ValueError, KeyError, ProofError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
