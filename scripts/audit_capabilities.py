# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
#!/usr/bin/env python3
"""Audit, reconcile, and generate capability truth-in-advertising matrices for COPS."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cops.capabilities import (
    CapabilityTruthError,
    audit_capabilities,
    build_capability_registry,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="audit_capabilities.py",
        description="Reconcile advertised capabilities and audit truth-in-advertising boundaries.",
    )
    parser.add_argument("--check", action="store_true", help="verify capabilities without modifying files")
    parser.add_argument("--write", action="store_true", help="write catalog/capabilities.json and update docs")
    parser.add_argument("--json", action="store_true", help="output structured JSON to stdout")
    args = parser.parse_args(argv)

    try:
        registry = build_capability_registry(ROOT)
        summary = audit_capabilities(ROOT, registry_data=registry)
    except CapabilityTruthError as err:
        print(f"audit failure: [{err.code}] {err.message}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(registry, indent=2))
        return 0

    print("Capability Truth-in-Advertising Audit Passed:")
    print(f"  Total Audited: {summary['total_capabilities']}")
    print(f"  Plugins: {summary['by_kind']['plugin']}")
    print(f"  Specialist Profiles: {summary['by_kind']['specialist']}")
    print(f"  Scenarios: {summary['by_kind']['scenario']}")
    print("  By Operational Mode:")
    for mode, count in summary["by_mode"].items():
        print(f"    - {mode}: {count}")

    if args.write:
        # Write catalog/capabilities.json
        cap_path = ROOT / "catalog" / "capabilities.json"
        cap_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote catalog/capabilities.json ({len(registry['capabilities'])} entries)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
