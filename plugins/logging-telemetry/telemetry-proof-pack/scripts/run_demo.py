#!/usr/bin/env python3
"""Deterministic demo runner for Telemetry Proof Pack."""

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
from proofpack.reporting import render_markdown_report


def run_scenario(name: str, directory: Path) -> None:
    print(f"\n================================================================================")
    print(f"  SCENARIO: {name}")
    print(f"  Location: {directory.relative_to(REPO_ROOT)}")
    print(f"================================================================================\n")

    manifest_file = directory / "manifest.json"
    if not manifest_file.is_file():
        print(f"ERROR: Missing manifest {manifest_file}", file=sys.stderr)
        return

    manifest = RunManifest.from_dict(json.loads(manifest_file.read_text(encoding="utf-8")))
    evidence = load_evidence_files(directory)
    report = correlate_pipeline_evidence(manifest, evidence)

    print(render_markdown_report(report))


def main() -> int:
    print("=== COPS Telemetry-to-Detection Proof Pack Demo ===")
    print("Traces synthetic markers through 5 pipeline stages:\n"
          "  1. source_emission\n"
          "  2. pipeline_routing (Cribl Stream)\n"
          "  3. destination_indexing (Splunk HEC or Sentinel LAW)\n"
          "  4. query_evaluation (Scheduled Detection Rule)\n"
          "  5. alert_creation (Notable Event or Sentinel Incident)")

    fixtures_dir = PLUGIN_ROOT / "fixtures"

    # 1. Healthy Cribl to Splunk
    run_scenario("Cribl to Splunk Route (Healthy)", fixtures_dir / "routes" / "cribl-splunk-route")

    # 2. Healthy Cribl to Sentinel
    run_scenario("Cribl to Sentinel Route (Healthy)", fixtures_dir / "routes" / "cribl-sentinel-route")

    # 3. Degraded Failure (Destination indexed but rule missed)
    run_scenario("HEC Indexed but Detection Missed (Degraded)", fixtures_dir / "failures" / "hec-indexed-rule-missed")

    # 4. Broken Failure (Missing Cribl stage / dropped)
    run_scenario("Missing Cribl Routing Stage (Broken)", fixtures_dir / "failures" / "missing-cribl-stage")

    # 5. Cross-Tenant Collision (Foreign tenant ID detected)
    run_scenario("Cross-Tenant Collision (Unresolved)", fixtures_dir / "failures" / "cross-tenant-collision")

    print("\n[OK] Demo completed all route traces and failure scenarios successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
