#!/usr/bin/env python3
"""Run the complete offline malicious-access investigation playback."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Any

PACKAGE = Path(__file__).resolve().parents[1]
CLI = PACKAGE / "scripts" / "investigate.py"
SOURCE = PACKAGE / "examples" / "intake" / "entra-signins.json"
EVALUATOR = PACKAGE / "vendor" / "sentinel-hunt-workbench" / "scripts" / "run_demo.py"
VARIANTS = {
    "malicious": ("malicious", "match"),
    "benign": ("benign", "no_escalation"),
    "insufficient_evidence": ("insufficient", "insufficient_evidence"),
}


class PlaybackError(RuntimeError):
    """A playback contract or subprocess assertion failed."""


def private_json(path: Path, value: Any) -> None:
    encoded = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run_json(*arguments: object) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(CLI), *map(str, arguments)],
        cwd=PACKAGE.parents[2],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
        env=environment,
    )
    if completed.returncode:
        raise PlaybackError(f"investigation command failed ({arguments[0]}): {completed.stderr.strip()}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise PlaybackError(f"investigation command returned invalid JSON ({arguments[0]})") from exc
    if not isinstance(value, dict):
        raise PlaybackError(f"investigation command returned an invalid object ({arguments[0]})")
    return value


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise PlaybackError(message)


@contextmanager
def output_directory(requested: Path | None) -> Iterator[tuple[Path, bool]]:
    """Yield a private output directory and whether the caller retained it."""
    if requested is not None:
        root = requested.resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        yield root, True
        return
    with tempfile.TemporaryDirectory(prefix="cops-soc-playback-") as raw:
        root = Path(raw)
        os.chmod(root, 0o700)
        yield root, False


def observation(variant: str, hunt_id: str, handoff: dict[str, Any]) -> dict[str, Any]:
    step_id = {"H01": "signin-triage", "H10": "token-audit"}[hunt_id]
    aliases = handoff["request"]["entities"]
    if variant == "insufficient_evidence":
        return {
            "id": f"result-{variant}-{hunt_id.lower()}",
            "step_id": step_id,
            "outcome": "unavailable",
            "coverage": "unavailable",
            "cost": 2 if hunt_id == "H01" else 3,
            "evidence": [],
        }
    malicious = variant == "malicious"
    assessments = [
        {
            "hypothesis_id": "malicious-activity",
            "stance": "supports" if malicious else "refutes",
            "reason": (
                "The reference fixture satisfies the malicious invariant for this hunt."
                if malicious
                else "The benign counterfactual lacks the malicious invariant for this hunt."
            ),
        },
        {
            "hypothesis_id": "benign-explanation",
            "stance": "refutes" if malicious else "supports",
            "reason": (
                "The reference fixture conflicts with the bounded benign explanation."
                if malicious
                else "The counterfactual is consistent with the bounded benign explanation."
            ),
        },
    ]
    record = json.dumps({"variant": variant, "hunt_id": hunt_id, "aliases": aliases}, sort_keys=True)
    return {
        "id": f"result-{variant}-{hunt_id.lower()}",
        "step_id": step_id,
        "outcome": "supports" if malicious else "refutes",
        "coverage": "complete",
        "cost": 2 if hunt_id == "H01" else 3,
        "evidence": [
            {
                "id": f"ev-{variant}-{hunt_id.lower()}",
                "source": f"sentinel-{hunt_id.lower()}-reference-fixture",
                "record_ref": sha256(record.encode()).hexdigest(),
                "scope": {
                    "tenant": handoff["request"]["scope"]["tenant"],
                    "workspace": handoff["request"]["scope"]["workspace"],
                },
                "event_time": "2026-01-01T04:20:00Z" if hunt_id == "H01" else "2026-01-01T04:30:00Z",
                "entities": aliases,
                "assessments": assessments,
                "summary": (
                    f"Offline {hunt_id} reference fixture observed the expected "
                    f"{'malicious invariant' if malicious else 'benign counterfactual'}."
                ),
            }
        ],
    }


def run_variant(root: Path, variant: str, evaluation: dict[str, Any]) -> dict[str, Any]:
    variant_dir = root / variant
    variant_dir.mkdir(mode=0o700)
    initial = variant_dir / "01-intake.json"
    run_json(
        "intake",
        "--case-id",
        f"case-malicious-access-{variant}",
        "--tenant",
        "tenant-a",
        "--workspace",
        "workspace-a",
        "--start",
        "2026-01-01T00:00:00Z",
        "--end",
        "2026-01-02T00:00:00Z",
        "--sources",
        f"entra:{SOURCE}",
        "--out",
        initial,
    )
    case = load(initial)
    assert_true(
        all(not item["assessments"] for item in case["evidence"]),
        "intake observations must begin without analyst assessments",
    )
    run_json("validate", initial)
    first_next = run_json("next", initial)
    assert_true(
        {item["step_id"] for item in first_next["candidates"]} == {"signin-triage", "token-audit"},
        "both independent inquiries must be ready after intake",
    )

    current = initial
    handoffs: dict[str, dict[str, Any]] = {}
    for sequence, hunt_id in enumerate(("H01", "H10"), start=2):
        step_id = {"H01": "signin-triage", "H10": "token-audit"}[hunt_id]
        handoff = run_json("handoff", current, "--step", step_id)
        handoffs[hunt_id] = handoff
        private_json(variant_dir / f"handoff-{hunt_id}.json", handoff)
        expected_kinds = {"H01": {"account", "ip"}, "H10": {"account", "app"}}[hunt_id]
        entity_kinds = {item["id"]: item["kind"] for item in load(current)["entities"]}
        assert_true(
            {entity_kinds[item] for item in handoff["request"]["entities"]} == expected_kinds,
            f"{hunt_id} must receive its kind-aware aliases",
        )
        evaluator_key, evaluator_outcome = VARIANTS[variant]
        evaluated = evaluation["hunts"][hunt_id][evaluator_key]
        assert_true(
            evaluated["passed"] is True and evaluated["actual_outcome"] == evaluator_outcome,
            f"{hunt_id} evaluator outcome did not satisfy the {variant} contract",
        )

        result_path = variant_dir / f"{sequence:02d}-{hunt_id.lower()}-observation.json"
        private_json(result_path, observation(variant, hunt_id, handoff))
        next_case = variant_dir / f"{sequence:02d}-case-after-{hunt_id.lower()}.json"
        run_json("import", current, result_path, "--out", next_case)
        current = next_case

        if variant == "insufficient_evidence" and hunt_id == "H01":
            revised_steps = load(current)["steps"]
            pending = next(item for item in revised_steps if item["id"] == "token-audit")
            pending["question"] = (
                "Can the independent consent trail reduce uncertainty despite unavailable sign-in telemetry?"
            )
            revision_path = variant_dir / "03-revised-steps.json"
            private_json(revision_path, revised_steps)
            revised_case = variant_dir / "03-revised-case.json"
            run_json("revise", current, revision_path, "--out", revised_case)
            current = revised_case
            run_json("validate", current)
            ready = run_json("next", current)
            assert_true(
                [item["step_id"] for item in ready["candidates"]] == ["token-audit"],
                "revised independent consent inquiry must remain eligible",
            )

    report_value = run_json("report", current)
    statuses = {item["id"]: item["status"] for item in report_value["hypotheses"]}
    if variant == "malicious":
        assert_true(
            statuses == {"malicious-activity": "support_observed", "benign-explanation": "refutation_observed"},
            "malicious observations must support only the malicious hypothesis",
        )
        conclusion = "malicious"
    elif variant == "benign":
        assert_true(
            statuses == {"malicious-activity": "refutation_observed", "benign-explanation": "support_observed"},
            "benign observations must support only the bounded benign hypothesis",
        )
        conclusion = "benign"
    else:
        assert_true(set(statuses.values()) == {"unresolved"}, "missing evidence must leave hypotheses unresolved")
        assert_true(len(report_value["coverage_gaps"]) == 2, "both unavailable inquiries must remain coverage gaps")
        assert_true(
            report_value["next"]["state"] == "needs_review" and report_value["next"]["reason"] == "no_progress",
            "two unavailable inquiries must stop for analyst review",
        )
        conclusion = "insufficient_evidence"
    assert_true("verdict" not in report_value, "the engine must not emit an automatic verdict")

    report_path = variant_dir / "final-report.json"
    private_json(report_path, report_value)
    export_dir = variant_dir / "handoff-export"
    exported = run_json("export-handoff", current, "--out-dir", export_dir)
    assert_true(
        Path(exported["json_path"]).is_file() and Path(exported["md_path"]).is_file(),
        "final JSON and Markdown handoffs must be exported",
    )
    return {
        "case_id": load(current)["id"],
        "conclusion": conclusion,
        "automatic": False,
        "reasons": [
            "The conclusion is an analyst playback assessment derived from explicit evidence stances.",
            "The hunt evaluator checks offline reference invariants and does not execute KQL or contact Sentinel.",
        ],
        "hypothesis_statuses": statuses,
        "coverage_gap_count": len(report_value["coverage_gaps"]),
        "final_case": str(current.relative_to(root)),
        "final_report": str(report_path.relative_to(root)),
        "handoff_json": str((export_dir / "handoff.json").relative_to(root)),
        "handoff_markdown": str((export_dir / "handoff.md").relative_to(root)),
        "assertions": {
            "unassessed_intake": True,
            "kind_aware_handoffs": True,
            "immutable_imports": True,
            "explicit_assessments": variant != "insufficient_evidence",
            "missing_evidence_not_benign": variant != "insufficient_evidence" or conclusion == "insufficient_evidence",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, help="New private directory for disposable playback artifacts.")
    args = parser.parse_args(argv)
    os.umask(0o077)
    disposable_root: Path | None = None
    try:
        with output_directory(args.out_dir) as (root, retained):
            if not retained:
                disposable_root = root
            evaluator_dir = root / "sentinel-evaluation"
            evaluated = subprocess.run(
                [sys.executable, str(EVALUATOR), "--out-dir", str(evaluator_dir)],
                cwd=PACKAGE.parents[2],
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            if evaluated.returncode:
                raise PlaybackError(f"vendored hunt evaluator failed: {evaluated.stderr.strip()}")
            evaluation = load(evaluator_dir / "evaluation-summary.json")
            assert_true(evaluation.get("status") == "passed", "vendored hunt evaluation did not pass")
            variants = {name: run_variant(root, name, evaluation) for name in VARIANTS}
            summary = {
                "schema_version": "soc-investigation.playback/v1",
                "status": "passed",
                "evidence_scope": "synthetic_contract_and_reference_semantics_only",
                "live_service_validation": "not_performed",
                "variants": variants,
                "assertions": {
                    "all_three_outcomes_completed": set(item["conclusion"] for item in variants.values())
                    == {"malicious", "benign", "insufficient_evidence"},
                    "no_automatic_verdicts": all(item["automatic"] is False for item in variants.values()),
                    "failed_or_empty_evidence_did_not_imply_benign": variants["insufficient_evidence"]["conclusion"]
                    == "insufficient_evidence",
                },
                "limitations": [
                    "The vendored evaluator checks reference invariants; it does not execute KQL.",
                    "No live Sentinel service, tenant, workspace, or connector was contacted.",
                    "Synthetic observations demonstrate workflow semantics and do not establish production efficacy.",
                ],
            }
            assert_true(all(summary["assertions"].values()), "final playback assertions failed")
            private_json(root / "playback-summary.json", summary)
            if retained:
                result = {
                    "status": "passed",
                    "out_dir": str(root),
                    "summary": str(root / "playback-summary.json"),
                }
            else:
                result = {
                    "status": "passed",
                    "artifacts": "validated_in_disposable_directory",
                    "playback_summary": summary,
                }
            print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, PlaybackError) as exc:
        error = str(exc)
        if disposable_root is not None:
            error = error.replace(str(disposable_root), "<disposable-output>")
        print(json.dumps({"status": "failed", "error": error}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
