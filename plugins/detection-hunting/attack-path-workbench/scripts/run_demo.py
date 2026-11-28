#!/usr/bin/env python3
"""Run and verify the illustrative attack-path playback."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from attackpath.cli import LEGACY_REPORT_FILES  # noqa: E402
from attackpath.cli import main as cli  # noqa: E402
from attackpath.core import query_intent  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def load(p):
    return json.loads(p.read_text())


def run(out):
    require(
        cli(["analyze", str(ROOT / "fixtures/illustrative/input.json"), "--output-dir", str(out)]) == 0,
        "illustrative analysis failed",
    )
    r = load(out / "report.json")
    g = load(out / "graph.json")
    c = load(out / "completion.json")
    require(len(r["supported_paths"]) == 1 and len(r["candidate_paths"]) == 1, "path classification changed")
    require(bool(g["nodes"] and g["edges"]), "analysis produced an empty graph")
    require(bool(r["quarantine"] and r["graph_exclusions"]), "analysis lost quarantine or exclusion evidence")
    require(r["attack_flow"]["status"] == "pending_reference_bundle", "attack-flow limitation changed")
    for name in LEGACY_REPORT_FILES:
        require(
            hashlib.sha256((out / name).read_bytes()).hexdigest() == c["files"][name],
            f"completion digest did not match {name}",
        )
    return r


def make_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    require(result.returncode == 0, f"could not create Windows junction: {result.stderr.strip()}")


def verify_windows_reparse_rejection(workspace: Path) -> None:
    if os.name != "nt":
        return

    input_target = workspace / "input-target"
    shutil.copytree(ROOT / "fixtures/illustrative", input_target)
    input_junction = workspace / "input-junction"
    make_junction(input_junction, input_target)
    try:
        output = workspace / "reparse-input-output"
        require(
            cli(["analyze", str(input_junction / "input.json"), "--output-dir", str(output)]) == 2,
            "junction-backed input was accepted",
        )
        require(not (output / "completion.json").exists(), "junction-backed input emitted a completion marker")
    finally:
        os.rmdir(input_junction)

    output_target = workspace / "output-target"
    output_target.mkdir()
    output_junction = workspace / "output-junction"
    make_junction(output_junction, output_target)
    try:
        redirected = output_junction / "reports"
        require(
            cli(
                [
                    "analyze",
                    str(ROOT / "fixtures/illustrative/input.json"),
                    "--output-dir",
                    str(redirected),
                ]
            )
            == 2,
            "junction-backed output parent was accepted",
        )
        require(not (output_target / "reports").exists(), "junction-backed output received report artifacts")
    finally:
        os.rmdir(output_junction)


def playback(w):
    a = run(w / "run-1")
    b = run(w / "run-2")
    require(a == b, "playback rerun changed the assessment")
    intent = query_intent("ILL-FINDING", "ILL-CROWN", "ILL-SCOPE")
    require(intent["render_status"] == "blocked_pending_docs", "Wiz query rendering was not blocked")
    (w / "wiz-query-intent.json").write_text(json.dumps(intent, indent=2, sort_keys=True) + "\n")
    bad = w / "invalid-input.json"
    bad.write_text("{}\n")
    require(cli(["analyze", str(bad), "--output-dir", str(w / "invalid-output")]) == 2, "invalid input was accepted")
    require(not (w / "invalid-output/completion.json").exists(), "failed analysis emitted a completion marker")
    verify_windows_reparse_rejection(w)
    return {
        "supported_paths": 1,
        "candidate_paths": 1,
        "quarantined_records": len(a["quarantine"]),
        "rerun_identical": True,
        "expected_failure": True,
        "wiz_status": intent["render_status"],
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
        with tempfile.TemporaryDirectory(prefix="attack-path-playback-") as d:
            print(json.dumps(playback(Path(d)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
