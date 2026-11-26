"""Coordinator for one offline review of the two bundled Detection Quality suites."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path

from cops._schema_validation import validate
from cops.catalog import find_plugin, load_json
from cops.evidence.canonical import digest
from cops.routing.catalog import get_specialist
from cops.routing.detection_quality import SKILL, SPECIALIST, WORKBENCH, route_bundled_review

STAGES = ("RULE-KQL-ENTRA-ANOMALOUS-SIGNIN", "RULE-SPL-DEFENDER-POWERSHELL-EXEC")
GAPS = {"missing_field_error", "false_negative", "false_positive"}
COUNTS = ("total_cases", "evaluated_cases", "schema_error_cases", "false_positives", "false_negatives")
SELECTION = {"specialist": SPECIALIST, "workbench": WORKBENCH, "skill": SKILL}
EXAMPLE = "Run both Detection Quality fixture sets and report the gaps."


def fingerprint(package: Path) -> str:
    files = [package / "skills" / SKILL / "SKILL.md", package / "schemas/report.schema.json"]
    files.extend(sorted((package / "detectionquality").glob("*.py")))
    for directory in ("rules", "fixtures"):
        paths = sorted((package / directory).glob("*.json"))
        if [p.stem for p in paths] != list(STAGES):
            raise ValueError("The packaged rules and fixtures must match the two pilot suites.")
        files.extend(paths)
    hashes = {p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    return digest(["cops.detection-quality-pilot/v1", SELECTION, hashes])


def evaluate(package: Path, stage: str) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(package / "detectionquality/cli.py"),
            "evaluate",
            "--rule",
            str(package / "rules" / f"{stage}.json"),
            "--fixtures",
            str(package / "fixtures" / f"{stage}.json"),
            "--json",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    return json.loads(proc.stdout)


def verify(package: Path, stage: str, report: dict) -> None:
    schema = load_json(package / "schemas/report.schema.json")
    schema.pop("$id", None)  # The bundled subset validator handles local schemas.
    validate(report, schema)
    suite = load_json(package / "fixtures" / f"{stage}.json")
    rule = load_json(package / "rules" / f"{stage}.json")
    if (
        suite["target_rule_id"] != stage
        or rule["rule_id"] != stage
        or any(report["rule"][k] != rule[k] for k in ("rule_id", "platform", "version", "name"))
        or report["evaluation_environment"] != "offline_reference_evaluator"
    ):
        raise ValueError("Report identity differs from the selected offline rule.")
    cases = report["case_results"]
    keys = ("case_id", "label", "expected_match")
    expected = [tuple(case[k] for k in keys) for case in suite["cases"]]
    if (
        not expected
        or len({row[0] for row in expected}) != len(expected)
        or [tuple(case[k] for k in keys) for case in cases] != expected
    ):
        raise ValueError("Report does not account for the labeled fixture cases.")

    metrics = report["metrics"]
    counts = dict.fromkeys(("true_positives", "false_positives", "true_negatives", "false_negatives"), 0)
    errors = 0
    missing_fields = set()
    for fixture, case in zip(suite["cases"], cases, strict=True):
        missing = {
            field
            for event in fixture["events"]
            if event.get("source") in (None, rule["source_data"]["primary_source"])
            for field in rule["required_fields"]
            if event.get(field) is None
        }
        missing_fields.update(missing)
        if bool(missing) != (case["outcome_classification"] == "missing_field_error"):
            raise ValueError("Reported telemetry gap disagrees with the fixture.")
        outcome = case["outcome_classification"]
        if outcome == "missing_field_error":
            errors += 1
            continue
        actual, wanted = case["actual_match"], case["expected_match"]
        kind = ("true" if actual == wanted else "false") + ("_positive" if actual else "_negative")
        boundary = actual == wanted and case["label"] != ("positive" if actual else "negative")
        if outcome != ("boundary_handled" if boundary else kind):
            raise ValueError("Case classification disagrees with its expected and actual match.")
        counts[kind + "s"] += 1
    tp, fp, fn = counts["true_positives"], counts["false_positives"], counts["false_negatives"]
    checks = {
        **counts,
        "total_cases": len(cases),
        "evaluated_cases": len(cases) - errors,
        "schema_error_cases": errors,
        "precision_on_labeled_fixtures": None if errors else round(tp / max(1, tp + fp), 4),
        "recall_on_labeled_fixtures": None if errors else round(tp / max(1, tp + fn), 4),
    }
    static = report["static_checks"]
    if (
        static["missing_fields"] != sorted(missing_fields)
        or static["schema_drift_detected"] != bool(missing_fields)
        or static["required_fields_present"] != (not missing_fields)
    ):
        raise ValueError("Reported missing fields disagree with the fixture telemetry.")
    if metrics != checks:
        raise ValueError("Report metrics disagree with the labeled case outcomes.")


def stage_report(db: sqlite3.Connection, package: Path, binding: str, stage: str) -> tuple[dict, str, str]:
    # Hold the write claim through evaluation. A competing resume waits, then
    # sees the committed receipt. Process death rolls back only the current suite.
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT report, receipt FROM accepted WHERE stage = ?", (stage,)).fetchone()
        report = json.loads(row[0]) if row else evaluate(package, stage)
        verify(package, stage, report)
        receipt = digest([binding, stage, report])
        if row and receipt != row[1]:
            raise ValueError("Saved suite receipt does not match the accepted report.")
        if fingerprint(package) != binding:
            raise ValueError("Pilot inputs changed. Start a new review.")
        if not row:
            db.execute("INSERT INTO accepted VALUES (?, ?, ?)", (stage, json.dumps(report), receipt))
    return report, receipt, "reused" if row else "evaluated"


def run_review(package: Path, directory: Path | None, resume: bool) -> dict:
    binding = fingerprint(package)
    if directory is None:
        home = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "cops/detection-quality"
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="run-", dir=home))
    elif not resume:
        directory.mkdir(mode=0o700)
    directory = directory.absolute()
    checkpoint = directory / "checkpoint.sqlite3"
    if resume and (not checkpoint.is_file() or checkpoint.is_symlink()):
        raise ValueError("Resume requires an existing pilot checkpoint.")
    suites = []
    uri = checkpoint.as_uri() + ("?mode=rw" if resume else "?mode=rwc")
    with closing(sqlite3.connect(uri, uri=True, timeout=65)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        if not resume:
            with db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE run (binding TEXT NOT NULL)")
                db.execute(
                    "CREATE TABLE accepted (stage TEXT PRIMARY KEY, report TEXT NOT NULL, receipt TEXT NOT NULL)"
                )
                db.execute("INSERT INTO run VALUES (?)", (binding,))
        if db.execute("SELECT binding FROM run").fetchall() != [(binding,)]:
            raise ValueError("Checkpoint belongs to a different pilot or input revision. Start a new review.")
        print(f"Detection Quality run directory: {directory}", file=sys.stderr, flush=True)
        for stage in STAGES:
            report, receipt, disposition = stage_report(db, package, binding, stage)
            suites.append(
                {
                    "rule_id": stage,
                    "platform": report["rule"]["platform"],
                    "disposition": disposition,
                    "receipt_digest": receipt,
                    "metrics": report["metrics"],
                    "missing_fields": report["static_checks"]["missing_fields"],
                    "gaps": [case for case in report["case_results"] if case["outcome_classification"] in GAPS],
                }
            )
    return {
        "schema_version": "cops.detection-quality-pilot/v1",
        "status": "verified",
        **SELECTION,
        "run_dir": str(directory),
        "evidence_scope": "bundled synthetic fixtures, offline reference evaluator",
        "totals": {k: sum(s["metrics"][k] for s in suites) for k in COUNTS},
        "suites": suites,
    }


def render(result: dict) -> str:
    if result["status"] != "verified":
        return result["message"]
    totals = result["totals"]
    lines = [
        f"Verified offline fixture review | {SPECIALIST} / {WORKBENCH} / {SKILL}",
        f"{totals['evaluated_cases']} of {totals['total_cases']} synthetic cases evaluated. "
        f"{totals['schema_error_cases']} schema errors, {totals['false_positives']} false positives, "
        f"{totals['false_negatives']} false negatives.",
    ]
    for suite in result["suites"]:
        metrics = suite["metrics"]
        lines.append(f"{suite['rule_id']} ({suite['disposition']})")
        for gap in suite["gaps"]:
            lines.append(f"  {gap['case_id']} [{gap['outcome_classification']}]: {gap['details']}")
        if metrics["schema_error_cases"]:
            lines.append("  Fixture precision and recall withheld until missing telemetry is supplied.")
        else:
            lines.append(
                f"  Fixture precision {metrics['precision_on_labeled_fixtures']}, "
                f"recall {metrics['recall_on_labeled_fixtures']}."
            )
    return "\n".join(lines)


def command_ask(args, root: Path) -> int:
    try:
        if args.resume is not None and args.run_dir is not None:
            raise ValueError("Use the original run directory with --resume.")
        registry = root / "agents/registry.json"
        decision = route_bundled_review(args.query, registry_path=registry) if args.resume is None else None
        if args.resume is None and decision is None:
            result = {"status": "clarification_required", "message": f"For both packaged fixture sets, ask: {EXAMPLE}"}
        else:
            profile = decision.primary_profile if decision else get_specialist(SPECIALIST, registry)
            if (
                profile.primary_plugin != WORKBENCH
                or SKILL not in profile.skills
                or SKILL not in profile.capabilities
                or "detectionquality" not in profile.tools
                or set(profile.required_permissions) != {"read_supplied_artifacts"}
                or profile.criticality != "normal"
                or profile.interactive_authorization_required
            ):
                raise ValueError("Registered profile no longer supports this offline review.")
            package = root / find_plugin(WORKBENCH, root).path
            result = run_review(package, args.resume or args.run_dir, args.resume is not None)
    except (ValueError, KeyError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        result = {"status": "failed", "message": str(exc)}
    print(json.dumps(result, indent=2) if args.json else render(result))
    return 0 if result["status"] == "verified" else 2
