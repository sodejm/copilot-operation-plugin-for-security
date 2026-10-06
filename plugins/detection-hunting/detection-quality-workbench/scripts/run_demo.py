# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
#!/usr/bin/env python3
"""Deterministic demo runner for Detection Quality Workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from detectionquality.evaluator import (
    evaluate_rule_suite,
)
from detectionquality.models import (
    FixtureSuite,
    Rule,
)
from detectionquality.reporting import (
    render_markdown_report,
)


def main() -> int:
    rules_dir = PLUGIN_ROOT / "rules"
    fixtures_dir = PLUGIN_ROOT / "fixtures"

    print("=== Detection Quality & Regression Workbench Demo ===")
    print(f"Loading detection rules from: {rules_dir.relative_to(REPO_ROOT)}")
    print(f"Loading fixture suites from:  {fixtures_dir.relative_to(REPO_ROOT)}\n")

    for r_path in sorted(rules_dir.glob("*.json")):
        f_path = fixtures_dir / r_path.name
        if not f_path.is_file():
            continue

        rule = Rule.from_dict(json.loads(r_path.read_text(encoding="utf-8")))
        suite = FixtureSuite.from_dict(json.loads(f_path.read_text(encoding="utf-8")))

        report_data = evaluate_rule_suite(rule, suite)
        report_md = render_markdown_report(report_data)
        print(report_md)
        print("-" * 80 + "\n")

    print("[OK] Successfully evaluated detection rules against labeled telemetry fixtures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
