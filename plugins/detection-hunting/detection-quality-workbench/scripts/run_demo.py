#!/usr/bin/env python3
"""Run the complete offline Detection Quality Workbench playback."""

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

from detectionquality.evaluator import evaluate_rule_suite  # noqa: E402
from detectionquality.models import FixtureSuite, QualityError, Rule  # noqa: E402
from detectionquality.reporting import render_json_report, render_markdown_report  # noqa: E402


def _assert_json_artifact(path: Path, schema_value: str) -> dict[str, object]:
    if not path.is_file() or path.stat().st_size == 0:
        raise QualityError(f"Missing or empty playback artifact: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != schema_value:
        raise QualityError(f"Unexpected schema in playback artifact: {path}")
    return payload


def _assert_markdown_artifact(path: Path) -> None:
    if not path.is_file() or not path.read_text(encoding="utf-8").strip():
        raise QualityError(f"Missing or empty playback artifact: {path}")


@contextmanager
def output_directory(requested: Path | None) -> Iterator[tuple[Path, bool]]:
    if requested is not None:
        requested.mkdir(parents=True, exist_ok=True)
        os.chmod(requested, 0o700)
        yield requested, True
        return
    with tempfile.TemporaryDirectory(prefix="detection-quality-playback-") as raw:
        path = Path(raw)
        os.chmod(path, 0o700)
        yield path, False


def _load_reports(rules_dir: Path, fixtures_dir: Path) -> dict[str, dict[str, object]]:
    if not rules_dir.is_dir():
        raise QualityError(f"Rules directory not found: {rules_dir}")
    if not fixtures_dir.is_dir():
        raise QualityError(f"Fixtures directory not found: {fixtures_dir}")
    rules = {path.stem: path for path in rules_dir.glob("*.json")}
    fixtures = {path.stem: path for path in fixtures_dir.glob("*.json")}
    if not rules:
        raise QualityError("No rule definitions found")
    if not fixtures:
        raise QualityError("No fixture suites found")
    if rules.keys() != fixtures.keys():
        missing = sorted(rules.keys() - fixtures.keys())
        orphaned = sorted(fixtures.keys() - rules.keys())
        raise QualityError(f"Rule/fixture mismatch: missing fixtures={missing}; orphaned fixtures={orphaned}")

    reports: dict[str, dict[str, object]] = {}
    for name in sorted(rules):
        rule = Rule.from_dict(json.loads(rules[name].read_text(encoding="utf-8")))
        suite = FixtureSuite.from_dict(json.loads(fixtures[name].read_text(encoding="utf-8")))
        reports[name] = evaluate_rule_suite(rule, suite)
    return reports


def run_playback(rules_dir: Path, fixtures_dir: Path, out_dir: Path) -> dict[str, object]:
    reports = _load_reports(rules_dir, fixtures_dir)
    rule_results: list[dict[str, object]] = []
    for name, report in reports.items():
        metrics = report["metrics"]
        if metrics["true_positives"] < 1 or metrics["true_negatives"] < 1:
            raise QualityError(f"{name}: fixtures must exercise positive and benign outcomes")
        if metrics["schema_error_cases"] < 1:
            raise QualityError(f"{name}: fixtures must exercise schema-drift failure")
        if metrics["false_positives"] or metrics["false_negatives"]:
            raise QualityError(f"{name}: unexpected fixture regression")
        if not any(case["outcome_classification"] == "missing_field_error" for case in report["case_results"]):
            raise QualityError(f"{name}: schema-drift case did not fail closed")
        report_dir = out_dir / "rules" / name
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "report.json").write_text(render_json_report(report), encoding="utf-8")
        (report_dir / "report.md").write_text(render_markdown_report(report), encoding="utf-8")
        written = _assert_json_artifact(report_dir / "report.json", "cops.detection-quality-report/v2")
        _assert_markdown_artifact(report_dir / "report.md")
        if written.get("metrics") != metrics:
            raise QualityError(f"{name}: written report metrics assertion failed")
        rule_results.append(
            {
                "rule_id": report["rule"]["rule_id"],
                "platform": report["rule"]["platform"],
                "metrics": metrics,
                "json_report": f"rules/{name}/report.json",
                "markdown_report": f"rules/{name}/report.md",
                "passed": True,
            }
        )

    if _load_reports(rules_dir, fixtures_dir) != reports:
        raise QualityError("playback rerun produced different evaluation reports")
    summary = {
        "schema_version": "cops.detection-quality-playback/v1",
        "status": "passed",
        "rules": rule_results,
        "rerun_equivalent": True,
        "evidence_scope": "labeled_offline_fixture_evaluation_only",
        "evidence_limitations": [
            "No Kusto, Splunk, SIEM scheduler, or provider API was used.",
            "Fixture precision and recall are not production efficacy measurements.",
        ],
    }
    (out_dir / "playback-summary.json").write_text(render_json_report(summary), encoding="utf-8")
    written_summary = _assert_json_artifact(out_dir / "playback-summary.json", "cops.detection-quality-playback/v1")
    if written_summary.get("status") != "passed":
        raise QualityError("Written playback summary did not pass validation")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-dir", type=Path, default=PLUGIN_ROOT / "rules")
    parser.add_argument("--fixtures-dir", type=Path, default=PLUGIN_ROOT / "fixtures")
    parser.add_argument("--out-dir", type=Path, help="Retain artifacts in this private directory")
    args = parser.parse_args(argv)
    try:
        with output_directory(args.out_dir) as (out_dir, retained):
            summary = run_playback(args.rules_dir, args.fixtures_dir, out_dir)
            print(json.dumps(summary, indent=2))
            location = f"retained at {out_dir}" if retained else "validated in a disposable directory"
            print(f"[OK] artifacts {location}")
        return 0
    except (OSError, ValueError, KeyError, QualityError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
