#!/usr/bin/env python3
"""Offline package gate validator for Detection Quality Workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from detectionquality.evaluator import evaluate_rule_suite
from detectionquality.models import FixtureSuite, Rule


def validate() -> int:
    print("[validate_package] Checking Detection Quality Workbench package integrity...")

    # 1. Check manifests and metadata
    json_files = [
        PLUGIN_ROOT / "package.json",
        PLUGIN_ROOT / "plugin.json",
        PLUGIN_ROOT / ".claude-plugin" / "plugin.json",
        PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
        PLUGIN_ROOT / "com.sodejm.copse" / "prerequisites.json",
        PLUGIN_ROOT / "schemas" / "rule.schema.json",
        PLUGIN_ROOT / "schemas" / "fixture.schema.json",
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
    skill_file = PLUGIN_ROOT / "skills" / "detection-quality-review" / "SKILL.md"
    if not skill_file.is_file():
        print(f"FAIL: Missing skill file {skill_file.relative_to(REPO_ROOT)}", file=sys.stderr)
        return 1
    content = skill_file.read_text(encoding="utf-8")
    if not content.startswith("---\nname: detection-quality-review\n"):
        print(f"FAIL: Skill file missing expected name frontmatter: {skill_file}", file=sys.stderr)
        return 1
    print("  OK: Validated skill definition and frontmatter.")

    # 3. Check rules and fixtures
    rules_dir = PLUGIN_ROOT / "rules"
    fixtures_dir = PLUGIN_ROOT / "fixtures"

    rule_files = list(rules_dir.glob("*.json"))
    if len(rule_files) < 2:
        print(f"FAIL: Expected at least 2 rules (1 KQL, 1 SPL), found {len(rule_files)}", file=sys.stderr)
        return 1

    platforms_found = set()
    for r_path in rule_files:
        rule = Rule.from_dict(json.loads(r_path.read_text(encoding="utf-8")))
        platforms_found.add(rule.platform)
        f_path = fixtures_dir / r_path.name
        if not f_path.is_file():
            print(f"FAIL: Missing matching fixture file for {r_path.name}", file=sys.stderr)
            return 1

        suite = FixtureSuite.from_dict(json.loads(f_path.read_text(encoding="utf-8")))
        rep = evaluate_rule_suite(rule, suite)

        # Invariants:
        if rep["metrics"]["true_positives"] < 1:
            print(f"FAIL: Rule {rule.rule_id} has zero true positives", file=sys.stderr)
            return 1
        if not rep["static_checks"]["schema_drift_detected"]:
            print(f"FAIL: Rule {rule.rule_id} fixtures did not test schema drift/missing field", file=sys.stderr)
            return 1

    if "sentinel_kql" not in platforms_found or "splunk_spl" not in platforms_found:
        print("FAIL: Expected both sentinel_kql and splunk_spl rule coverage", file=sys.stderr)
        return 1

    print(f"  OK: Validated {len(rule_files)} detection rules and fixture suites across {platforms_found}.")

    print("[validate_package] All checks passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
