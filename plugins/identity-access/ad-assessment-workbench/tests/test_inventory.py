"""Behavior and fail-closed boundaries for the offline AD inventory."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from adwb import InventoryError, analyze, load_export  # noqa: E402


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.export = load_export(PACKAGE / "fixtures" / "synthetic-two-forest.json")

    def test_two_forest_candidate_and_unknown(self) -> None:
        report = analyze(self.export)
        self.assertEqual(report, analyze(copy.deepcopy(self.export)))
        self.assertEqual(report["assessment"], "offline_structural_only")
        self.assertEqual(report["coverage"]["hosts"], {"host-a": "partial", "host-b": "unknown"})
        candidate, missing = report["queries"]
        self.assertEqual(candidate["status"], "candidate_paths")
        self.assertEqual(len(candidate["paths"]), 1)
        self.assertEqual(candidate["paths"][0]["status"], "candidate_requires_validation")
        self.assertEqual(
            candidate["paths"][0]["flags"],
            ["inferred_relationship", "partial_collection", "protected_identity", "trust_boundary"],
        )
        self.assertEqual(missing["status"], "not_found_in_collected_graph")
        self.assertEqual(missing["paths"], [])

    def test_conflicting_identity_rejected(self) -> None:
        bad = copy.deepcopy(self.export)
        bad["nodes"].append({**bad["nodes"][0], "kind": "group"})
        with self.assertRaisesRegex(InventoryError, "conflicting_identity"):
            analyze(bad)

    def test_cross_forest_privilege_rejected(self) -> None:
        bad = copy.deepcopy(self.export)
        bad["edges"][2]["kind"] = "privilege"
        with self.assertRaisesRegex(InventoryError, "unapproved_forest_boundary"):
            analyze(bad)

    def test_forest_coverage_needs_every_scoped_domain(self) -> None:
        report = analyze(self.export)
        self.assertEqual(report["coverage"]["forests"], {"forest-a": "complete", "forest-b": "partial"})
        expanded = copy.deepcopy(self.export)
        expanded["scope"]["domains"].append({"id": "domain-c", "forest": "forest-a"})
        self.assertEqual(analyze(expanded)["coverage"]["forests"]["forest-a"], "partial")

    def test_depth_limited_search_does_not_claim_path_absence(self) -> None:
        export = copy.deepcopy(self.export)
        for index in range(8):
            export["nodes"].append(
                {
                    "id": f"chain-{index}",
                    "kind": "group",
                    "forest": "forest-a",
                    "domain": "domain-a",
                    "protected": False,
                }
            )
            if index:
                export["edges"].append(
                    {
                        "id": f"chain-edge-{index}",
                        "source": f"chain-{index - 1}",
                        "target": f"chain-{index}",
                        "kind": "member_of",
                        "collector_id": "directory-a",
                        "collected_at": "2026-01-01T11:00:00Z",
                        "completeness": "complete",
                        "support": "observed",
                    }
                )
        export["queries"] = [{"start": "chain-0", "goal": "chain-7"}]
        result = analyze(export)["queries"][0]
        self.assertEqual(result["status"], "search_incomplete")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["paths"], [])

    def test_found_paths_still_report_incomplete_search(self) -> None:
        export = copy.deepcopy(self.export)
        for index in range(7):
            export["nodes"].append(
                {
                    "id": f"branch-{index}",
                    "kind": "group",
                    "forest": "forest-a",
                    "domain": "domain-a",
                    "protected": False,
                }
            )
            export["edges"].append(
                {
                    "id": f"branch-edge-{index}",
                    "source": "user-a" if index == 0 else f"branch-{index - 1}",
                    "target": f"branch-{index}",
                    "kind": "member_of",
                    "collector_id": "directory-a",
                    "collected_at": "2026-01-01T11:00:00Z",
                    "completeness": "complete",
                    "support": "observed",
                }
            )
        result = analyze(export)["queries"][0]
        self.assertEqual(result["status"], "search_incomplete")
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["paths"]), 1)

    def test_edge_cannot_outlive_collector(self) -> None:
        bad = copy.deepcopy(self.export)
        bad["edges"][0]["collected_at"] = "2026-01-02T00:00:00Z"
        with self.assertRaisesRegex(InventoryError, "invalid_timestamp"):
            analyze(bad)

    def test_timestamps_are_canonical_and_bounded(self) -> None:
        accepted = copy.deepcopy(self.export)
        accepted["edges"][0]["collected_at"] = "2026-01-01T11:00:00.123456Z"
        analyze(accepted)
        for timestamp in (
            "2026-01-01T11:00:00.1234567Z",
            "2026-01-01T11:00:00." + "1" * 100_000 + "Z",
        ):
            with self.subTest(length=len(timestamp)):
                bad = copy.deepcopy(self.export)
                bad["edges"][0]["collected_at"] = timestamp
                with self.assertRaisesRegex(InventoryError, "invalid_timestamp"):
                    analyze(bad)

    def test_host_collector_requires_typed_host_endpoint(self) -> None:
        bad = copy.deepcopy(self.export)
        next(node for node in bad["nodes"] if node["id"] == "host-a")["kind"] = "principal"
        with self.assertRaisesRegex(InventoryError, "collector_scope_mismatch"):
            analyze(bad)

    def test_duplicate_json_fields_fail_closed(self) -> None:
        for raw in (
            '{"schema_version":"0","schema_version":"1.0"}',
            '{"scope":{"hosts":[],"hosts":[]}}',
            '{"scope":NaN}',
        ):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "export.json"
                path.write_text(raw, encoding="utf-8")
                with self.assertRaisesRegex(InventoryError, "invalid_json"):
                    load_export(path)

    def test_deep_json_fails_with_structured_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.json"
            for depth in (65, 1200):
                with self.subTest(depth=depth):
                    path.write_text("[" * depth + "0" + "]" * depth, encoding="utf-8")
                    with self.assertRaisesRegex(InventoryError, "invalid_json"):
                        load_export(path)

    def test_package_root_command_runs(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/analyze.py", "fixtures/synthetic-two-forest.json"],
            cwd=PACKAGE,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["queries"][0]["status"], "candidate_paths")

    def test_unknown_fields_rejected(self) -> None:
        bad = copy.deepcopy(self.export)
        bad["nodes"][0]["display_name"] = "sensitive person name"
        with self.assertRaisesRegex(InventoryError, "invalid_structure"):
            analyze(bad)

    def test_symlink_input_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "export.json"
            link.symlink_to(PACKAGE / "fixtures" / "synthetic-two-forest.json")
            with self.assertRaisesRegex(InventoryError, "invalid_file"):
                load_export(link)

    def test_result_has_no_raw_attributes(self) -> None:
        report = json.dumps(analyze(self.export))
        self.assertNotIn("display_name", report)
        self.assertNotIn("password", report)

    def test_malformed_nested_values_fail_with_inventory_error(self) -> None:
        for field, index, key, value in (
            ("collections", 0, "source", {}),
            ("collections", 0, "domain", []),
            ("nodes", 0, "kind", {}),
            ("edges", 0, "support", {}),
            ("edges", 0, "completeness", {}),
        ):
            with self.subTest(field=field, key=key):
                bad = copy.deepcopy(self.export)
                bad[field][index][key] = value
                with self.assertRaises(InventoryError):
                    analyze(bad)
        bad = copy.deepcopy(self.export)
        bad["nodes"].append(None)
        with self.assertRaisesRegex(InventoryError, "invalid_structure"):
            analyze(bad)


if __name__ == "__main__":
    unittest.main()
