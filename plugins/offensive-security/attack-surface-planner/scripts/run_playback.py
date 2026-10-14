#!/usr/bin/env python3
"""Run the deterministic offline planning playback and its failure case."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"playback validation failed: {message}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "scripts/playback/manifest.json")
    args = parser.parse_args()
    contract = json.loads(args.manifest.read_text(encoding="utf-8"))
    source = (args.manifest.parent / contract["scope_manifest"]).resolve()
    expected = contract["expected"]

    with tempfile.TemporaryDirectory(prefix="cops-planner-playback-") as raw:
        work = Path(raw)
        fixture = work / "fixture"
        shutil.copytree(source.parent, fixture)
        copied_scope = fixture / source.name
        command = [sys.executable, str(ROOT / "scripts/plan.py"), str(copied_scope)]
        first, second = run(command), run(command)
        if first.returncode or second.returncode:
            raise SystemExit(first.stderr or second.stderr)
        one, two = json.loads(first.stdout), json.loads(second.stdout)
        require(one == two, "rerun changed the canonical plan")
        require(one["network_requests"] == expected["network_requests"], "network request count changed")
        require(one["summary"] == expected["summary"], "scope summary changed")
        require(len(one["test_plan"]) == expected["test_plan_count"], "proposal count changed")
        require([item["kind"] for item in one["sources"]] == expected["source_kinds"], "source kinds changed")
        require(
            {item["decision"] for item in one["surface_map"]} == {"in_scope", "excluded", "unresolved"},
            "scope decisions are incomplete",
        )
        require(
            all(item["method"].startswith("passive-review") for item in one["test_plan"]),
            "an active proposal escaped the passive-only gate",
        )

        rejected = json.loads(copied_scope.read_text(encoding="utf-8"))
        rejected["mode"] = "active"
        bad = work / "active.json"
        bad.write_text(json.dumps(rejected), encoding="utf-8")
        failure = run([sys.executable, str(ROOT / "scripts/plan.py"), str(bad)])
        require(failure.returncode == 2 and "input gate:" in failure.stderr, "active mode was not rejected")

    print(
        json.dumps(
            {
                "playback": "attack-surface-planner",
                "status": "passed",
                "rerun_equal": True,
                "failure_path": "active mode rejected",
                "summary": one["summary"],
                "test_plan_count": len(one["test_plan"]),
                "network_requests": one["network_requests"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
