#!/usr/bin/env python3
"""Run the repository collector and validate a human-authored recommendation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "skills/repository-context/scripts/collect-repository-context.py"
SCHEMA_VERSION = "cops.logging-advisor-playback/v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"playback validation failed: {message}")


def validate_contract(contract: dict) -> None:
    required = {"schema_version", "recommendation", "required_headings", "required_fields", "expected"}
    require(set(contract) == required, "invalid manifest fields")
    require(contract["schema_version"] == SCHEMA_VERSION, "unsupported manifest schema")
    require(bool(contract["required_headings"]), "manifest must require recommendation headings")
    require(bool(contract["required_fields"]), "manifest must require recommendation fields")
    require(set(contract["expected"]) == {"languages", "framework", "iac_and_cloud"}, "invalid expected fields")


def collect(target: Path, *limits: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(COLLECTOR), *limits, str(target)], text=True, capture_output=True, check=False
    )


def recommendation_errors(text: str, contract: dict) -> list[str]:
    errors = [f"missing heading: {item}" for item in contract["required_headings"] if item not in text]
    errors.extend(f"missing field: {item}" for item in contract["required_fields"] if f"**{item}**:" not in text)
    return errors


def semantic(value):
    """Normalize unordered report collections for a semantic rerun comparison."""
    if isinstance(value, dict):
        return {key: semantic(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        items = [semantic(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "scripts/playback/manifest.json")
    args = parser.parse_args()
    contract = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_contract(contract)
    recommendation = (args.manifest.parent / contract["recommendation"]).read_text(encoding="utf-8")
    expected = contract["expected"]

    with tempfile.TemporaryDirectory(prefix="cops-logging-playback-") as raw:
        fixture = Path(raw)
        (fixture / "service.py").write_text("import logging\nfrom flask import Flask\n", encoding="utf-8")
        (fixture / "main.tf").write_text('resource "aws_cloudwatch_log_group" "app" {}\n', encoding="utf-8")
        (fixture / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        (fixture / "README.md").write_text("Synthetic logging playback fixture.\n", encoding="utf-8")
        first, second = collect(fixture), collect(fixture)
        if first.returncode or second.returncode:
            raise SystemExit(first.stderr or second.stderr)
        one, two = json.loads(first.stdout), json.loads(second.stdout)
        require(semantic(one) == semantic(two), "collector semantic rerun changed")
        require(one["languages"] == expected["languages"], "detected languages changed")
        require(expected["framework"] in one["frameworks_and_libraries"], "expected framework was not detected")
        require(sorted(one["iac_and_cloud"]) == sorted(expected["iac_and_cloud"]), "IaC detection changed")
        require(
            one["coverage"] == "complete" and not one["incomplete_coverage"], "full scan reported incomplete coverage"
        )
        require(not recommendation_errors(recommendation, contract), "recommendation template failed validation")

        partial = collect(fixture, "--max-files", "1")
        partial_data = json.loads(partial.stdout)
        require(
            partial.returncode == 0 and partial_data["incomplete_coverage"],
            "limited scan did not disclose partial coverage",
        )
        require(bool(partial_data["partial_scan_notice"]), "limited scan omitted its partial coverage notice")
        broken = recommendation.replace("- **Acceptance Criteria**:", "- **Removed Field**:")
        require(
            "missing field: Acceptance Criteria" in recommendation_errors(broken, contract),
            "missing recommendation field was not rejected",
        )

    print(
        json.dumps(
            {
                "playback": "security-logging-advisor",
                "status": "passed",
                "scanned_files_count": one["scanned_files_count"],
                "rerun_semantically_equal": True,
                "failure_paths": ["partial scan disclosed", "missing recommendation field rejected"],
                "recommendation_author": "human-authored fixture",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
