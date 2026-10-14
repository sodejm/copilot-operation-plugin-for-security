#!/usr/bin/env python3
"""Run the synthetic Linux privilege-boundary import demonstration."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def import_case(source: Path) -> dict:
    result = subprocess.run(
        [sys.executable, str(PACKAGE / "scripts/assess.py"), str(source)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    require(result.returncode == 0, result.stderr)
    report = json.loads(result.stdout)
    require(report["mode"] == "offline_import", "assessment did not report offline import mode")
    require(report["source"]["kind"] == "synthetic_lab", "assessment did not preserve synthetic origin")
    return report


def main() -> int:
    cases = {}
    expected = {
        "positive": "reported_canary_crossing",
        "negative": "reported_canary_blocked",
        "fixed": "reported_canary_blocked",
    }
    for name, classification in expected.items():
        fixture = PACKAGE / "fixtures" / "synthetic" / f"host_linux_{name}_v1.json"
        report = import_case(fixture)
        require(report == import_case(fixture), f"{name} playback was not repeatable")
        require(report["observations"][0]["classification"] == classification, f"{name} classification changed")
        require(report["observations"][0]["cleanup_reported"] is True, f"{name} cleanup was not reported")
        require(report["counts"][classification] == 1, f"{name} count did not match its classification")
        require(len(report["coverage"]) == 8, f"{name} coverage inventory was incomplete")
        cases[name] = {
            "source_kind": report["source"]["kind"],
            "counts": report["counts"],
            "coverage": report["coverage"],
        }
    with tempfile.TemporaryDirectory(prefix="cops-host-playback-") as temporary:
        fixture = PACKAGE / "fixtures/synthetic/host_linux_positive_v1.json"
        record = json.loads(fixture.read_text(encoding="utf-8"))
        record["host"]["kernel_release"] = "unknown"
        source = Path(temporary) / "unknown.json"
        source.write_text(json.dumps(record), encoding="utf-8")
        source.chmod(0o600)
        unresolved = import_case(source)
        require(
            all(row["decision"] == "unresolved" for row in unresolved["observations"]),
            "unknown host context did not remain unresolved",
        )
        require(
            unresolved["counts"]["reported_canary_crossing"] == 0,
            "unknown host context was counted as a canary crossing",
        )
        cases["unknown_context"] = {"counts": unresolved["counts"]}

        record = json.loads(fixture.read_text(encoding="utf-8"))
        record["observations"][0]["canary"]["cleanup_verified"] = False
        source.write_text(json.dumps(record), encoding="utf-8")
        rejected = subprocess.run(
            [sys.executable, str(PACKAGE / "scripts/assess.py"), str(source)],
            capture_output=True, text=True, timeout=15, check=False,
        )
        require(rejected.returncode == 2 and not rejected.stdout, "unverified cleanup was not rejected")
        require("cleanup" in rejected.stderr, "cleanup rejection did not explain the failure")
        cases["unverified_cleanup"] = {"rejected": True}
    print(json.dumps({"status": "passed", "mode": "offline_import", "cases": cases}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
