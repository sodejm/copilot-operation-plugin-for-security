#!/usr/bin/env python3
"""Run the synthetic two-forest assessment as a checked playback."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from adwb import InventoryError, analyze, load_export  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(out):
    report = analyze(load_export(ROOT / "fixtures/synthetic-two-forest.json"))
    out.mkdir()
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    paths = [q for q in report["queries"] if q.get("status") == "candidate_paths"]
    missing = [q for q in report["queries"] if q.get("status") == "not_found_in_collected_graph"]
    require(bool(paths and missing), "playback must contain candidate and missing-path results")
    flags = set(paths[0]["paths"][0]["flags"])
    require(
        {"inferred_relationship", "partial_collection", "trust_boundary", "protected_identity"} <= flags,
        "candidate path did not preserve its evidence limitations",
    )
    return report


def playback(w):
    a = run(w / "run-1")
    b = run(w / "run-2")
    require(a == b, "playback rerun changed the assessment")
    bad = w / "duplicate-key.json"
    bad.write_text('{"schema_version":"1.0","schema_version":"1.0"}\n')
    try:
        load_export(bad)
    except (InventoryError, OSError, ValueError) as e:
        (w / "expected-failure.txt").write_text(type(e).__name__ + "\n")
    else:
        raise AssertionError("duplicate JSON key was accepted")
    return {
        "queries": len(a["queries"]),
        "candidate_paths": sum(len(q["paths"]) for q in a["queries"]),
        "rerun_identical": True,
        "expected_failure": True,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path)
    a = ap.parse_args()
    if a.workspace and a.workspace.exists():
        ap.error("--workspace must not already exist")
    if a.workspace:
        a.workspace.mkdir(parents=True)
        s = playback(a.workspace)
        (a.workspace / "playback-summary.json").write_text(json.dumps(s, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"workspace": str(a.workspace), **s}, sort_keys=True))
    else:
        with tempfile.TemporaryDirectory(prefix="ad-playback-") as d:
            print(json.dumps(playback(Path(d)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
