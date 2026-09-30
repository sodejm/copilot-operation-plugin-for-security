#!/usr/bin/env python3
"""Deterministic demo runner for Entra Identity Workbench."""

from __future__ import annotations

import sys
from pathlib import Path

# Add plugin root to sys.path so entrawb can be imported cleanly
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from entrawb.analysis import analyze_identity_graph
from entrawb.graph import build_identity_graph
from entrawb.ingestion import ingest_tenant_export
from entrawb.reporting import render_markdown_report


def main() -> int:
    manifest_path = PLUGIN_ROOT / "fixtures" / "tenants" / "contoso-corp" / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: Fixture manifest not found at {manifest_path}", file=sys.stderr)
        return 1

    print(f"=== Entra Identity Workbench Demo ===")
    print(f"Loading tenant export from: {manifest_path.relative_to(REPO_ROOT)}")

    manifest, sources = ingest_tenant_export(manifest_path)
    graph = build_identity_graph(manifest, sources)
    hypotheses = analyze_identity_graph(graph)

    report_md = render_markdown_report(graph, hypotheses)
    print("\n" + report_md)
    print(f"\n[OK] Successfully analyzed {len(graph.nodes)} entities and identified {len(hypotheses)} exposure hypotheses.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
