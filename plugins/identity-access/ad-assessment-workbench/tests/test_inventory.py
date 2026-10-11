"""Behavior and fail-closed boundaries for the offline AD inventory."""

from __future__ import annotations

import copy
import json
import sys
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
        self.assertEqual(candidate["paths"][0]["flags"], ["inferred_relationship", "partial_collection",
                                                           "protected_identity", "trust_boundary"])
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
            export["nodes"].append({"id": f"chain-{index}", "kind": "group", "forest": "forest-a",
                                    "domain": "domain-a", "protected": False})
            if index:
                export["edges"].append({"id": f"chain-edge-{index}", "source": f"chain-{index-1}",
                                        "target": f"chain-{index}", "kind": "member_of",
                                        "collector_id": "directory-a", "collected_at": "2026-01-01T11:00:00Z",
                                        "completeness": "complete", "support": "observed"})
        export["queries"] = [{"start": "chain-0", "goal": "chain-7"}]
        result = analyze(export)["queries"][0]
        self.assertEqual(result["status"], "search_incomplete")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["paths"], [])

    def test_edge_cannot_outlive_collector(self) -> None:
        bad = copy.deepcopy(self.export)
        bad["edges"][0]["collected_at"] = "2026-01-02T00:00:00Z"
        with self.assertRaisesRegex(InventoryError, "invalid_timestamp"):
            analyze(bad)

    def test_unknown_fields_rejected(self) -> None:
        bad = copy.deepcopy(self.export)
        bad["nodes"][0]["display_name"] = "sensitive person name"
        with self.assertRaisesRegex(InventoryError, "invalid_structure"):
            analyze(bad)

    def test_symlink_input_rejected(self) -> None:
        import tempfile
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
