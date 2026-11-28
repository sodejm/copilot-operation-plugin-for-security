#!/usr/bin/env python3
"""Run the complete offline Sentinel Hunt Workbench playback."""

from __future__ import annotations

import argparse
import copy
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

from huntwb.errors import HuntWorkbenchError  # noqa: E402
from huntwb.evaluator import reference_match, run_library  # noqa: E402
from huntwb.paths import FIXTURES_DIR, load_hunt, load_hunts, load_json, write_json  # noqa: E402
from huntwb.rendering import compatibility_report, render_hunt  # noqa: E402

PARAMETERS = {
    "start_time": "2026-01-01T00:00:00Z",
    "end_time": "2026-01-01T02:00:00Z",
    "workspace_id": "00000000-0000-4000-8000-000000000001",
    "tenant_id": "00000000-0000-4000-8000-000000000002",
    "correlation_window": "2h",
}
EVALUATED_HUNTS = ("H01", "H02", "H10")
CATEGORIES = {
    "malicious": "true_positive",
    "benign": "benign_counterfactual",
    "insufficient": "schema_surface",
}
MODELED_SCHEMA_FAILURES = frozenset({"unknown_table", "unknown_field", "unsupported_operator", "unverified_surface"})


def _assert_json_artifact(path: Path, schema_key: str, schema_value: str) -> dict[str, object]:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"missing or empty playback artifact: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get(schema_key) != schema_value:
        raise RuntimeError(f"unexpected schema in playback artifact: {path}")
    return payload


@contextmanager
def output_directory(requested: Path | None) -> Iterator[tuple[Path, bool]]:
    if requested is not None:
        requested.mkdir(parents=True, exist_ok=True)
        os.chmod(requested, 0o700)
        yield requested, True
        return
    with tempfile.TemporaryDirectory(prefix="sentinel-hunt-playback-") as raw:
        path = Path(raw)
        os.chmod(path, 0o700)
        yield path, False


def _evaluate(hunt_id: str, fixtures_root: Path = FIXTURES_DIR) -> dict[str, object]:
    hunt = load_hunt(hunt_id)
    scenarios = load_json(fixtures_root / f"{hunt_id}.json")["scenarios"]
    outcomes: dict[str, object] = {}
    for label, category in CATEGORIES.items():
        scenario = next(item for item in scenarios if item["category"] == category)
        fixture_expected = scenario["expected_qualification_outcome"]
        if category == "schema_surface":
            evaluation_input = copy.deepcopy(scenario["input"])
            controls = evaluation_input.get("controls", {})
            validation_contract = controls.get("validation_contract") if isinstance(controls, dict) else None
            # The offline reference evaluator does not parse KQL. Translate the
            # curated schema/surface contract into its modeled static-failure input.
            if validation_contract in MODELED_SCHEMA_FAILURES:
                controls["static_validation_failed"] = True
            result = reference_match(hunt, evaluation_input)
            expected = "insufficient_evidence"
            actual = (
                "insufficient_evidence"
                if result.reason == "modeled_static_validation_failure"
                else ("match" if result.matched else "no_escalation")
            )
            passed = actual == expected and fixture_expected == "validation_failure"
            reason = result.reason
        else:
            result = reference_match(hunt, scenario["input"])
            actual = "match" if result.matched else "no_escalation"
            expected = fixture_expected
            passed, reason = actual == expected, result.reason
        outcomes[label] = {
            "scenario_id": scenario["id"],
            "fixture_category": category,
            "fixture_expected_qualification_outcome": fixture_expected,
            "expected_outcome": expected,
            "actual_outcome": actual,
            "reason": reason,
            "passed": passed,
        }
    return outcomes


def run_playback(out_dir: Path, fixtures_root: Path = FIXTURES_DIR) -> dict[str, object]:
    rendered: list[dict[str, str]] = []
    compatibility_by_hunt: dict[str, object] = {}
    for hunt in load_hunts():
        hunt_id = hunt["id"]
        compatibility_by_hunt[hunt_id] = compatibility_report(hunt_id)
        for surface, state in sorted(hunt["surface_support"].items()):
            if state != "supported":
                continue
            artifact = render_hunt(hunt_id, surface, PARAMETERS)
            relative = Path("rendered") / hunt_id / f"{surface}.json"
            write_json(out_dir / relative, artifact)
            written = _assert_json_artifact(out_dir / relative, "artifact_schema", "huntwb.rendered-hunt/v1")
            if written.get("hunt_brief", {}).get("id") != hunt_id or written.get("surface", {}).get("id") != surface:
                raise RuntimeError(f"rendered artifact identity mismatch: {relative}")
            rendered.append({"hunt_id": hunt_id, "surface": surface, "path": str(relative)})
    evaluations = {hunt_id: _evaluate(hunt_id, fixtures_root) for hunt_id in EVALUATED_HUNTS}
    passed = all(outcome["passed"] for hunts in evaluations.values() for outcome in hunts.values())
    evaluation_summary = {
        "schema_version": "huntwb.playback-evaluation/v1",
        "status": "passed" if passed else "failed",
        "evaluator": "reference_invariant_evaluator",
        "evidence_scope": "synthetic_contract_and_reference_semantics_only",
        "live_service_validation": "not_performed",
        "hunts": evaluations,
    }
    if not passed:
        raise RuntimeError("one or more playback evaluation assertions failed")
    qualification = {
        "schema_version": "huntwb.qualification/v1",
        **run_library(),
    }
    if (
        qualification["status"] != "passed"
        or qualification["semantic_mutations_caught"] != qualification["semantic_mutations"]
    ):
        raise RuntimeError("qualification drift or mutation assertion failed")
    if {hunt_id: _evaluate(hunt_id, fixtures_root) for hunt_id in EVALUATED_HUNTS} != evaluations:
        raise RuntimeError("playback rerun produced different evaluation results")
    compatibility = {
        "schema_version": "huntwb.playback-compatibility/v1",
        "hunts": compatibility_by_hunt,
    }
    write_json(out_dir / "compatibility-report.json", compatibility)
    write_json(out_dir / "evaluation-summary.json", evaluation_summary)
    write_json(out_dir / "qualification-report.json", qualification)
    _assert_json_artifact(out_dir / "compatibility-report.json", "schema_version", "huntwb.playback-compatibility/v1")
    _assert_json_artifact(out_dir / "evaluation-summary.json", "schema_version", "huntwb.playback-evaluation/v1")
    _assert_json_artifact(out_dir / "qualification-report.json", "schema_version", "huntwb.qualification/v1")
    summary = {
        "schema_version": "huntwb.playback-summary/v1",
        "status": "passed",
        "rendered_artifact_count": len(rendered),
        "rendered_artifacts": rendered,
        "evaluation_summary": "evaluation-summary.json",
        "qualification_report": "qualification-report.json",
        "compatibility_report": "compatibility-report.json",
        "rerun_equivalent": True,
        "evidence_limitations": [
            "No KQL parser, Kusto engine, Microsoft Sentinel, Defender, ADX, or tenant was used.",
            "Results establish offline fixture and contract behavior only; analyst review is required.",
        ],
    }
    write_json(out_dir / "playback-summary.json", summary)
    written_summary = _assert_json_artifact(
        out_dir / "playback-summary.json", "schema_version", "huntwb.playback-summary/v1"
    )
    if written_summary.get("status") != "passed":
        raise RuntimeError("written playback summary did not pass validation")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures-root", type=Path, default=FIXTURES_DIR)
    parser.add_argument("--out-dir", type=Path, help="Retain artifacts in this private directory")
    args = parser.parse_args(argv)
    try:
        with output_directory(args.out_dir) as (out_dir, retained):
            summary = run_playback(out_dir, args.fixtures_root)
            print(json.dumps(summary, indent=2))
            print(
                f"[OK] artifacts {'retained at ' + str(out_dir) if retained else 'validated in a disposable directory'}"
            )
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, StopIteration, HuntWorkbenchError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
