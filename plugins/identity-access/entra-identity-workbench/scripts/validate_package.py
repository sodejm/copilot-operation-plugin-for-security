# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
#!/usr/bin/env python3
"""Offline package gate validator for Entra Identity Workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from entrawb.analysis import (
    analyze_identity_graph,
)
from entrawb.graph import (
    build_identity_graph,
)
from entrawb.ingestion import (
    ingest_tenant_export,
)
from entrawb.reporting import (
    render_json_report,
    render_markdown_report,
)


def validate() -> int:
    print("[validate_package] Checking Entra Identity Workbench package integrity...")

    # 1. Check manifests and metadata
    json_files = [
        PLUGIN_ROOT / "package.json",
        PLUGIN_ROOT / "plugin.json",
        PLUGIN_ROOT / ".claude-plugin" / "plugin.json",
        PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
        PLUGIN_ROOT / "org.cops" / "prerequisites.json",
        PLUGIN_ROOT / "schemas" / "manifest.schema.json",
        PLUGIN_ROOT / "schemas" / "graph.schema.json",
        PLUGIN_ROOT / "schemas" / "report.schema.json",
    ]

    for p in json_files:
        if not p.is_file():
            print(f"FAIL: Missing required file {p.relative_to(REPO_ROOT)}", file=sys.stderr)
            return 1
        try:
            json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"FAIL: Malformed JSON in {p.relative_to(REPO_ROOT)}: {e}", file=sys.stderr)
            return 1
    print(f"  OK: Validated {len(json_files)} package configuration and schema files.")

    # 2. Check skill frontmatter
    skill_file = PLUGIN_ROOT / "skills" / "entra-identity-analysis" / "SKILL.md"
    if not skill_file.is_file():
        print(f"FAIL: Missing skill file {skill_file.relative_to(REPO_ROOT)}", file=sys.stderr)
        return 1
    content = skill_file.read_text(encoding="utf-8")
    if not content.startswith("---\nname: entra-identity-analysis\n"):
        print(f"FAIL: Skill file missing expected name frontmatter: {skill_file}", file=sys.stderr)
        return 1
    print("  OK: Validated skill definition and frontmatter.")

    # 3. Ingestion and Graph Invariants
    manifest_path = PLUGIN_ROOT / "fixtures" / "tenants" / "contoso-corp" / "manifest.json"
    manifest, sources = ingest_tenant_export(manifest_path)
    graph = build_identity_graph(manifest, sources)

    # Invariant: all edges connect existing nodes
    node_ids = set(graph.nodes.keys())
    for edge in graph.edges:
        if edge.source_id not in node_ids:
            print(f"FAIL: Edge source '{edge.source_id}' not found in graph nodes", file=sys.stderr)
            return 1
        if edge.target_id not in node_ids:
            print(f"FAIL: Edge target '{edge.target_id}' not found in graph nodes", file=sys.stderr)
            return 1
    print(f"  OK: Graph invariants hold: {len(graph.nodes)} nodes, {len(graph.edges)} edges.")

    # 4. Analysis and Reporting
    hypotheses = analyze_identity_graph(graph)
    if not hypotheses:
        print("FAIL: Analysis yielded zero hypotheses on fixture data", file=sys.stderr)
        return 1

    report_dict = render_json_report(graph, hypotheses)
    if report_dict.get("tenant_id") != graph.tenant_id:
        print("FAIL: Report tenant_id mismatch", file=sys.stderr)
        return 1
    if len(report_dict.get("hypotheses", [])) != len(hypotheses):
        print("FAIL: Report hypothesis count mismatch", file=sys.stderr)
        return 1

    report_md = render_markdown_report(graph, hypotheses)
    if "# Entra Identity & Agent Exposure Review" not in report_md:
        print("FAIL: Markdown report missing expected header", file=sys.stderr)
        return 1
    print(f"  OK: Verified analysis and reporting ({len(hypotheses)} hypotheses generated).")

    print("[validate_package] All checks passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
