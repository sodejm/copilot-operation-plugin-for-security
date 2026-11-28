#!/usr/bin/env python3
"""Run a retained or temporary end-to-end Entra evidence playback."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from entrawb.analysis import analyze_identity_graph  # noqa: E402
from entrawb.graph import build_identity_graph  # noqa: E402
from entrawb.ingestion import EntraError, ingest_tenant_export  # noqa: E402
from entrawb.reporting import render_json_report, render_markdown_report  # noqa: E402
from entrawb.validation import (  # noqa: E402
    validate_graph_artifact,
    validate_report_artifact,
)

AS_OF = datetime(2026, 9, 30, 18, tzinfo=UTC)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def assess(manifest, out):
    m, s = ingest_tenant_export(manifest)
    g = build_identity_graph(m, s, as_of=AS_OF)
    h = analyze_identity_graph(g)
    gd = g.to_dict()
    r = render_json_report(g, h)
    validate_graph_artifact(gd)
    validate_report_artifact(r)
    require(bool(gd["nodes"] and gd["edges"] and r["hypotheses"]), "assessment produced no graph or hypotheses")
    out.mkdir()
    (out / "graph.json").write_text(json.dumps(gd, indent=2, sort_keys=True) + "\n")
    (out / "report.json").write_text(json.dumps(r, indent=2, sort_keys=True) + "\n")
    (out / "report.md").write_text(render_markdown_report(g, h))
    return gd, r


def playback(w):
    p = ROOT / "fixtures/tenants/contoso-corp/manifest.json"
    g1, r1 = assess(p, w / "run-1")
    g2, r2 = assess(p, w / "run-2")
    r1.pop("analyzed_at", None)
    r2.pop("analyzed_at", None)
    require(g1 == g2 and r1 == r2, "playback rerun changed the graph or assessment")
    bad = w / "expected-failure.json"
    bad.write_text("{}\n")
    try:
        ingest_tenant_export(bad)
    except (EntraError, OSError, ValueError) as e:
        (w / "expected-failure.txt").write_text(type(e).__name__ + "\n")
    else:
        raise AssertionError("invalid manifest was accepted")
    return {
        "nodes": len(g1["nodes"]),
        "edges": len(g1["edges"]),
        "hypotheses": len(r1["hypotheses"]),
        "rerun_equivalent": True,
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
        with tempfile.TemporaryDirectory(prefix="entra-playback-") as d:
            print(json.dumps(playback(Path(d)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
