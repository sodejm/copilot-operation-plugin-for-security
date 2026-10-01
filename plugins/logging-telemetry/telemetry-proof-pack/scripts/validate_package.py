#!/usr/bin/env python3
"""Offline package gate validator for Telemetry Proof Pack."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from proofpack.cli import load_evidence_files
from proofpack.correlator import correlate_pipeline_evidence
from proofpack.models import RunManifest


def validate() -> int:
    print("[validate_package] Checking Telemetry Proof Pack package integrity...")

    # 1. Check manifests and metadata
    json_files = [
        PLUGIN_ROOT / "package.json",
        PLUGIN_ROOT / "plugin.json",
        PLUGIN_ROOT / ".claude-plugin" / "plugin.json",
        PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
        PLUGIN_ROOT / "com.sodejm.copse" / "prerequisites.json",
        PLUGIN_ROOT / "schemas" / "manifest.schema.json",
        PLUGIN_ROOT / "schemas" / "proof.schema.json",
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
    skill_file = PLUGIN_ROOT / "skills" / "telemetry-proof-tracing" / "SKILL.md"
    if not skill_file.is_file():
        print(f"FAIL: Missing skill file {skill_file.relative_to(REPO_ROOT)}", file=sys.stderr)
        return 1
    content = skill_file.read_text(encoding="utf-8")
    if not content.startswith("---\nname: telemetry-proof-tracing\n"):
        print(f"FAIL: Skill file missing expected name frontmatter: {skill_file}", file=sys.stderr)
        return 1
    print("  OK: Validated skill definition and frontmatter.")

    # 3. Check route fixtures
    routes_dir = PLUGIN_ROOT / "fixtures" / "routes"
    splunk_dir = routes_dir / "cribl-splunk-route"
    sentinel_dir = routes_dir / "cribl-sentinel-route"

    if not splunk_dir.is_dir() or not sentinel_dir.is_dir():
        print("FAIL: Missing required route directories (Splunk and Sentinel)", file=sys.stderr)
        return 1

    # Splunk route verification
    splunk_man = RunManifest.from_dict(json.loads((splunk_dir / "manifest.json").read_text(encoding="utf-8")))
    splunk_ev = load_evidence_files(splunk_dir)
    splunk_rep = correlate_pipeline_evidence(splunk_man, splunk_ev)
    if splunk_rep["pipeline_health"] != "healthy" or splunk_rep["summary"]["observed_stages_count"] != 5:
        print("FAIL: Splunk route did not evaluate as healthy 5-stage trace", file=sys.stderr)
        return 1

    # Sentinel route verification
    sentinel_man = RunManifest.from_dict(json.loads((sentinel_dir / "manifest.json").read_text(encoding="utf-8")))
    sentinel_ev = load_evidence_files(sentinel_dir)
    sentinel_rep = correlate_pipeline_evidence(sentinel_man, sentinel_ev)
    if sentinel_rep["pipeline_health"] != "healthy" or sentinel_rep["summary"]["observed_stages_count"] != 5:
        print("FAIL: Sentinel route did not evaluate as healthy 5-stage trace", file=sys.stderr)
        return 1

    print("  OK: Validated Cribl-to-Splunk and Cribl-to-Sentinel healthy proof routes.")

    # 4. Check failure scenarios
    failures_dir = PLUGIN_ROOT / "fixtures" / "failures"

    # Degraded check
    deg_dir = failures_dir / "hec-indexed-rule-missed"
    deg_man = RunManifest.from_dict(json.loads((deg_dir / "manifest.json").read_text(encoding="utf-8")))
    deg_ev = load_evidence_files(deg_dir)
    deg_rep = correlate_pipeline_evidence(deg_man, deg_ev)
    if deg_rep["pipeline_health"] != "degraded":
        print("FAIL: hec-indexed-rule-missed did not evaluate as degraded", file=sys.stderr)
        return 1

    # Broken check
    brk_dir = failures_dir / "missing-cribl-stage"
    brk_man = RunManifest.from_dict(json.loads((brk_dir / "manifest.json").read_text(encoding="utf-8")))
    brk_ev = load_evidence_files(brk_dir)
    brk_rep = correlate_pipeline_evidence(brk_man, brk_ev)
    if brk_rep["pipeline_health"] != "broken":
        print("FAIL: missing-cribl-stage did not evaluate as broken", file=sys.stderr)
        return 1

    # Collision check
    col_dir = failures_dir / "cross-tenant-collision"
    col_man = RunManifest.from_dict(json.loads((col_dir / "manifest.json").read_text(encoding="utf-8")))
    col_ev = load_evidence_files(col_dir)
    col_rep = correlate_pipeline_evidence(col_man, col_ev)
    if col_rep["stages_breakdown"][0]["status"] != "unresolved":
        print("FAIL: cross-tenant-collision did not set stage status to unresolved", file=sys.stderr)
        return 1

    print("  OK: Validated failure modes (degraded, broken, cross-tenant collision).")
    print("[validate_package] All checks passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
