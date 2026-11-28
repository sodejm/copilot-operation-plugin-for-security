#!/usr/bin/env python3
"""Run six offline mock scenarios, verify reruns, and exercise denial."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "cops.foundry-harness-playback/v1"
OUTCOME_VOCABULARY = [
    "model_output_only",
    "attempted_tool_call",
    "denied_tool_call",
    "executed_mock_effect",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"playback validation failed: {message}")


def validate_contract(contract: dict) -> None:
    require(set(contract) == {"schema_version", "scenarios", "expected"}, "invalid manifest fields")
    require(contract["schema_version"] == SCHEMA_VERSION, "unsupported manifest schema")
    expected = contract["expected"]
    require(set(expected) == {"scenario_ids", "outcome_vocabulary", "summary"}, "invalid expected fields")
    require(len(expected["scenario_ids"]) == 6, "manifest must pin six scenario IDs")
    require(len(set(expected["scenario_ids"])) == 6, "scenario IDs must be unique")
    require(expected["outcome_vocabulary"] == OUTCOME_VOCABULARY, "unsupported outcome vocabulary")


def invoke(scenarios: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "foundryharness/cli.py"), "evaluate", "--scenarios-dir", str(scenarios), "--json"],
        text=True,
        capture_output=True,
        check=False,
    )


def stable(report: dict) -> dict:
    report = json.loads(json.dumps(report))
    report.pop("report_id", None)
    report.pop("evaluated_at", None)
    for finding in report["findings"]:
        finding.pop("trace_id", None)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "scripts/playback/manifest.json")
    args = parser.parse_args()
    contract = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_contract(contract)
    source = (args.manifest.parent / contract["scenarios"]).resolve()
    expected = contract["expected"]

    with tempfile.TemporaryDirectory(prefix="cops-foundry-playback-") as raw:
        work = Path(raw)
        scenarios = work / "scenarios"
        shutil.copytree(source, scenarios)
        first, second = invoke(scenarios), invoke(scenarios)
        if first.returncode or second.returncode:
            raise SystemExit(first.stderr or second.stderr)
        one, two = json.loads(first.stdout), json.loads(second.stdout)
        require(stable(one) == stable(two), "semantic rerun changed")
        require(one["summary"] == expected["summary"], "outcome summary changed")
        require(
            [item["scenario_id"] for item in one["findings"]] == expected["scenario_ids"],
            "scenario order or membership changed",
        )
        require(
            all(item["authorization_decision"] == "deny" for item in one["findings"]),
            "an unauthorized mock action was not denied",
        )
        require(
            set(item["outcome_level"] for item in one["findings"]) <= set(expected["outcome_vocabulary"]),
            "an unsupported outcome level was emitted",
        )
        require(one["environment"] == "mock-sandbox-offline", "execution left the mock offline environment")

        invalid = work / "invalid"
        invalid.mkdir()
        broken = json.loads(next(scenarios.glob("*.json")).read_text(encoding="utf-8"))
        broken.pop("approved_test_environment", None)
        (invalid / "broken.json").write_text(json.dumps(broken), encoding="utf-8")
        failure = invoke(invalid)
        require(
            failure.returncode == 2 and "No valid scenarios found" in failure.stderr,
            "scenario without approval was not rejected",
        )

    print(
        json.dumps(
            {
                "playback": "foundry-agent-harness",
                "status": "passed",
                "scenario_count": one["summary"]["total_scenarios"],
                "denied_count": one["summary"]["denied_tool_call_count"],
                "rerun_semantically_equal": True,
                "failure_path": "scenario missing approval rejected",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
