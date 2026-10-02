"""Positive, denial, recovery, and deterministic-output controls."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from attackpath.core import (GateError, analyze, audit_report, canonical,
                             file_hash, load_json, query_intent, rank_paths,
                             trace_paths, validate_input)
from attackpath.search import SearchLimits


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "illustrative"


class WorkbenchTests(unittest.TestCase):
    def analyze_changed_export(self, change) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            export = json.loads((FIXTURE / "export.json").read_text())
            change(export)
            export_path = folder / "export.json"
            export_path.write_bytes(canonical(export))
            data = json.loads((FIXTURE / "input.json").read_text())
            data["sources"][0]["sha256"] = file_hash(export_path)
            data["sources"][0]["record_count"] = len(export["records"])
            manifest = folder / "input.json"
            manifest.write_bytes(canonical(data))
            return analyze(manifest)

    def test_positive_and_candidate_are_separate(self) -> None:
        report = analyze(FIXTURE / "input.json")
        self.assertEqual(1, len(report["supported_paths"]))
        self.assertEqual(1, len(report["candidate_paths"]))
        supported = report["supported_paths"][0]
        candidate = report["candidate_paths"][0]
        self.assertEqual("unrated", supported["impact"]["business_rating"])
        self.assertEqual(["confidentiality"], supported["impact"]["potential_cia"])
        self.assertEqual(3, supported["blast_radius"]["evidenced_asset_count"])
        self.assertEqual("medium", supported["confidence"])
        self.assertEqual("low", candidate["confidence"])
        self.assertEqual(["ILL-SERVICE"], supported["blast_radius"]["evidenced_service_ids"])
        self.assertEqual(2, len(supported["blast_radius"]["service_dependency_evidence_refs"]))
        self.assertEqual(1, candidate["blast_radius"]["evidenced_asset_count"])
        self.assertEqual(0, candidate["blast_radius"]["evidenced_service_count"])
        self.assertTrue(candidate["gaps"])
        self.assertEqual("warning_quarantined", report["gate_results"]["G2"])
        self.assertEqual("warning_excluded", report["gate_results"]["G3"])
        self.assertEqual("pending_reference_bundle", report["attack_flow"]["status"])
        self.assertIsNone(report["actions"][0]["owner"])
        self.assertEqual("transition", report["actions"][0]["target_type"])
        self.assertEqual(report["actions"][0]["target_id"], supported["steps"][0]["edge_id"])

    def test_finding_on_crown_jewel_is_direct_structural_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "export.json").write_bytes((FIXTURE / "export.json").read_bytes())
            data = json.loads((FIXTURE / "input.json").read_text())
            data["context"]["crown_jewels"][0]["asset_ref"] = "ILL-ASSET-A"
            manifest = folder / "input.json"
            manifest.write_bytes(canonical(data))
            report = analyze(manifest)
        direct = next(path for path in report["supported_paths"] if path["target"] == "ILL-ASSET-A")
        self.assertEqual([], direct["steps"])
        self.assertEqual([], direct["impact"]["potential_cia"])
        self.assertEqual(1, direct["blast_radius"]["evidenced_asset_count"])
        action = next(action for action in report["actions"] if action["path_id"] == direct["path_id"])
        self.assertEqual("finding", action["target_type"])
        self.assertEqual(direct["start_finding"], action["target_id"])

    def test_source_hash_denial_and_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "export.json").write_bytes((FIXTURE / "export.json").read_bytes())
            data = json.loads((FIXTURE / "input.json").read_text())
            data["sources"][0]["sha256"] = "0" * 64
            manifest = folder / "input.json"
            manifest.write_bytes(canonical(data))
            with self.assertRaisesRegex(GateError, "SHA-256 mismatch"):
                analyze(manifest)
            data["sources"][0]["sha256"] = file_hash(folder / "export.json")
            manifest.write_bytes(canonical(data))
            self.assertEqual(1, len(analyze(manifest)["supported_paths"]))

    def test_unknown_decision_field_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "export.json").write_bytes((FIXTURE / "export.json").read_bytes())
            data = json.loads((FIXTURE / "input.json").read_text())
            data["context"]["likelihood"] = 0.99
            manifest = folder / "input.json"
            manifest.write_bytes(canonical(data))
            with self.assertRaisesRegex(GateError, "unknown=.*likelihood"):
                analyze(manifest)

    def test_repeatable_and_query_blocked(self) -> None:
        one = analyze(FIXTURE / "input.json")
        two = analyze(FIXTURE / "input.json")
        self.assertEqual(canonical(one), canonical(two))
        intent = query_intent("ILL-FINDING", "ILL-CROWN", "ILL-SCOPE")
        self.assertEqual("blocked_pending_docs", intent["render_status"])
        self.assertEqual("[PENDING_WIZ_DOCS]", intent["api_operation"])
        self.assertEqual("[PENDING_WIZ_DOCS]", intent["documentation_profile_id"])
        self.assertEqual("[PENDING_WIZ_DOCS]", intent["operation_profile_id"])

    def test_search_receipt_is_bounded_and_bound_to_run_identity(self) -> None:
        manifest = FIXTURE / "input.json"
        ordinary = analyze(manifest)
        limited = analyze(manifest, search_limits={"expansions": 1})
        self.assertEqual("attackpath.report/v2", limited["schema_version"])
        self.assertFalse(limited["search"]["complete"])
        self.assertEqual("expansion_limit", limited["search"]["stop_reason"])
        self.assertEqual("best_discovered", limited["search"]["ranking_scope"])
        self.assertEqual(1, limited["search"]["consumed"]["expansions"])
        self.assertNotEqual(ordinary["run"]["run_id"], limited["run"]["run_id"])
        _, sources = validate_input(load_json(manifest), manifest.parent)
        audit_report(limited, sources)
        changed = copy.deepcopy(limited)
        changed["search"]["consumed"]["expansions"] += 1
        with self.assertRaisesRegex(GateError, "search receipt"):
            audit_report(changed, sources)

    def test_search_hard_ceiling_and_report_byte_budget(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            SearchLimits.from_values({"expansions": 50_001})
        with self.assertRaisesRegex(ValueError, "positive integer"):
            SearchLimits.from_values({"frontier": True})
        with self.assertRaisesRegex(GateError, "report_byte_limit"):
            analyze(FIXTURE / "input.json", search_limits={"report_bytes": 1})

    def test_emitted_limit_labels_discovered_ranking(self) -> None:
        report = analyze(FIXTURE / "input.json", search_limits={"emitted_paths": 1})
        self.assertEqual("emitted_path_limit", report["search"]["stop_reason"])
        self.assertFalse(report["search"]["complete"])
        self.assertEqual("best_discovered", report["search"]["ranking_scope"])
        self.assertEqual(1, report["search"]["consumed"]["emitted_paths"])

    def test_frontier_complete_and_partial_limits_stop_search(self) -> None:
        nodes = {name: {"record": {"node_type": "asset"}, "class": "observed",
                        "evidence_id": f"N-{name}", "confidence": "high"}
                 for name in ("A", "B", "C")}
        findings = [{"record": {"id": "F", "asset_ref": "A"}, "class": "observed",
                     "evidence_id": "E-F", "confidence": "high", "scope": "S"}]
        edges = [{"record": {"id": f"E-{target}", "from": "A", "to": target,
                             "relation": "reachable_from", "preconditions": ["finding_on_asset"],
                             "postcondition": "network_reachability", "support": "observed"},
                  "evidence_id": f"E-{target}",
                  "class": "observed", "confidence": "high"} for target in ("B", "C")]
        crowns = [{"asset_ref": "B", "priority": 1}, {"asset_ref": "C", "priority": 2}]
        for overrides, targets, reason in (
            ({"frontier": 1}, crowns, "frontier_limit"),
            ({"complete_paths": 1}, crowns, "complete_path_limit"),
            ({"partial_paths": 1}, [], "partial_path_limit"),
        ):
            with self.subTest(reason=reason):
                _, _, receipt = trace_paths(nodes, findings, edges, targets,
                                            SearchLimits.from_values(overrides))
                self.assertEqual(reason, receipt["stop_reason"])
                self.assertFalse(receipt["complete"])
                self.assertEqual("best_discovered", receipt["ranking_scope"])

    def test_v1_report_audits_without_claiming_search_completeness(self) -> None:
        manifest = FIXTURE / "input.json"
        report = analyze(manifest)
        report["schema_version"] = "attackpath.report/v1"
        del report["search"]
        del report["run"]["search_policy_sha256"]
        _, sources = validate_input(load_json(manifest), manifest.parent)
        audit_report(report, sources)

    def test_claim_audit_rejects_cited_but_false_relationship_and_impact(self) -> None:
        manifest = FIXTURE / "input.json"
        _, sources = validate_input(load_json(manifest), manifest.parent)
        report = analyze(manifest)
        changed = copy.deepcopy(report)
        changed["supported_paths"][0]["steps"][0]["relation"] = "permission_to_act"
        with self.assertRaisesRegex(GateError, "G7: path"):
            audit_report(changed, sources)
        changed = copy.deepcopy(report)
        changed["supported_paths"][0]["impact"]["potential_cia"] = ["availability"]
        with self.assertRaisesRegex(GateError, "G7: path"):
            audit_report(changed, sources)
        changed = copy.deepcopy(report)
        changed["graph"]["edges"][0]["to"] = "ILL-ASSET-A"
        with self.assertRaisesRegex(GateError, "G7: graph relationship"):
            audit_report(changed, sources)
        changed = copy.deepcopy(report)
        changed["actions"][0]["proposal"] = "Close this finding; the attacker is confirmed."
        with self.assertRaisesRegex(GateError, "G7: proposed action"):
            audit_report(changed, sources)

    def test_claim_audit_rejects_changed_cited_source_record(self) -> None:
        manifest = FIXTURE / "input.json"
        _, sources = validate_input(load_json(manifest), manifest.parent)
        report = analyze(manifest)
        changed = copy.deepcopy(report)
        changed["evidence"][0]["record"]["id"] = "FABRICATED"
        with self.assertRaisesRegex(GateError, "G7: evidence record"):
            audit_report(changed, sources)

    def test_partial_branch_retained_when_another_branch_reaches_target(self) -> None:
        def change(export):
            export["records"].append({"record_type": "node", "id": "ILL-DEAD-END",
                                      "node_type": "asset", "scope": "ILL-SCOPE",
                                      "observed_at": "2026-01-01T00:00:00Z", "support": "observed"})
            export["records"].append({"record_type": "edge", "id": "ILL-DEAD-END-EDGE",
                                      "from": "ILL-ASSET-A", "to": "ILL-DEAD-END",
                                      "relation": "reachable_from", "preconditions": ["finding_on_asset"],
                                      "postcondition": "network_reachability", "scope": "ILL-SCOPE",
                                      "observed_at": "2026-01-01T00:00:00Z", "support": "observed"})
        report = self.analyze_changed_export(change)
        self.assertEqual(1, len(report["supported_paths"]))
        self.assertTrue(any(p["stopped_at"] == "ILL-DEAD-END" for p in report["partial_paths"]))

    def test_missing_capability_cannot_claim_cia(self) -> None:
        def change(export):
            for row in export["records"]:
                if row.get("id") == "ILL-PERMISSION":
                    row["preconditions"] = ["control"]
        report = self.analyze_changed_export(change)
        self.assertEqual([], report["supported_paths"])
        path = next(p for p in report["candidate_paths"] if any(s["edge_id"] == "ILL-PERMISSION" for s in p["steps"]))
        self.assertIn("missing capability control", " ".join(path["gaps"]))
        self.assertEqual([], path["impact"]["potential_cia"])
        self.assertEqual(2, path["blast_radius"]["evidenced_asset_count"])

    def test_scope_mismatch_is_quarantined_and_not_joined(self) -> None:
        def change(export):
            for row in export["records"]:
                if row.get("id") == "ILL-PERMISSION":
                    row["scope"] = "OTHER-SCOPE"
        report = self.analyze_changed_export(change)
        self.assertEqual([], report["supported_paths"])
        self.assertTrue(any("scope mismatch" in q["reason"] for q in report["quarantine"]))

    def test_nonexistent_impact_profile_and_cross_snapshot_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "export.json").write_bytes((FIXTURE / "export.json").read_bytes())
            data = json.loads((FIXTURE / "input.json").read_text())
            manifest = folder / "input.json"
            data["context"]["impact_profile_id"] = "unapproved"
            manifest.write_bytes(canonical(data))
            with self.assertRaisesRegex(GateError, "approved impact profiles are not installed"):
                analyze(manifest)
            data["context"]["impact_profile_id"] = None
            second = copy.deepcopy(data["sources"][0])
            second["source_id"] = "SECOND"
            second["exported_at"] = "2026-01-03T00:00:00Z"
            data["sources"].append(second)
            manifest.write_bytes(canonical(data))
            with self.assertRaisesRegex(GateError, "cross-snapshot joins"):
                analyze(manifest)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"schema_version":"attackpath.input/v1","schema_version":"attackpath.input/v1"}')
            with self.assertRaisesRegex(GateError, "duplicate JSON key"):
                analyze(path)

    def test_equivalent_edges_keep_all_supporting_sources(self) -> None:
        def change(export):
            duplicate = copy.deepcopy(next(row for row in export["records"] if row.get("id") == "ILL-PERMISSION"))
            duplicate["id"] = "ILL-PERMISSION-SECOND"
            export["records"].append(duplicate)
        report = self.analyze_changed_export(change)
        self.assertEqual(1, len(report["supported_paths"]))
        path = report["supported_paths"][0]
        self.assertEqual(2, len(path["steps"][-1]["supporting_evidence_refs"]))
        self.assertTrue(set(path["steps"][-1]["supporting_evidence_refs"]) <= set(path["evidence_refs"]))

    def test_different_preconditions_are_distinct_paths(self) -> None:
        def change(export):
            alternative = copy.deepcopy(next(row for row in export["records"] if row.get("id") == "ILL-PERMISSION"))
            alternative["id"] = "ILL-PERMISSION-NEEDS-CONTROL"
            alternative["preconditions"] = ["control"]
            export["records"].append(alternative)
        report = self.analyze_changed_export(change)
        self.assertEqual(1, len(report["supported_paths"]))
        self.assertEqual(2, len(report["candidate_paths"]))

    def test_hypothetical_node_cannot_make_supported_path_or_blast_radius(self) -> None:
        def change(export):
            for row in export["records"]:
                if row.get("id") == "ILL-ASSET-B":
                    row["support"] = "hypothesis"
        report = self.analyze_changed_export(change)
        self.assertEqual([], report["supported_paths"])
        path = next(p for p in report["candidate_paths"] if len(p["steps"]) == 2)
        self.assertEqual(1, path["blast_radius"]["evidenced_asset_count"])
        self.assertEqual([], path["impact"]["potential_cia"])
        self.assertTrue(any("hypothetical node" in gap for gap in path["gaps"]))

    def test_hypothetical_finding_has_no_evidenced_blast_radius(self) -> None:
        def change(export):
            for row in export["records"]:
                if row.get("id") == "ILL-FINDING":
                    row["support"] = "hypothesis"
        report = self.analyze_changed_export(change)
        self.assertEqual([], report["supported_paths"])
        self.assertTrue(all(p["blast_radius"]["evidenced_asset_count"] == 0 for p in report["candidate_paths"]))

    def test_service_count_breaks_equal_asset_rank(self) -> None:
        report = analyze(FIXTURE / "input.json")
        first = copy.deepcopy(report["supported_paths"][0])
        second = copy.deepcopy(first)
        first["path_id"] = "P-A"
        first["blast_radius"]["evidenced_service_count"] = 0
        second["path_id"] = "P-Z"
        second["blast_radius"]["evidenced_service_count"] = 1
        self.assertEqual("P-Z", rank_paths([first, second], report["context"]["crown_jewels"])[0]["path_id"])

    def test_invalid_edge_types_are_excluded(self) -> None:
        def change(export):
            for row in export["records"]:
                if row.get("id") == "ILL-ASSET-B":
                    row["node_type"] = "service"
        report = self.analyze_changed_export(change)
        self.assertEqual([], report["supported_paths"])
        self.assertTrue(any("reachable_from requires" in e["reason"] for e in report["graph_exclusions"]))

    def test_hypothetical_dependency_does_not_count_service(self) -> None:
        def change(export):
            for row in export["records"]:
                if row.get("id") == "ILL-DEPENDENCY":
                    row["support"] = "hypothesis"
        report = self.analyze_changed_export(change)
        self.assertEqual(0, report["supported_paths"][0]["blast_radius"]["evidenced_service_count"])

    def test_invalid_dependency_target_is_excluded(self) -> None:
        def change(export):
            for row in export["records"]:
                if row.get("id") == "ILL-CROWN":
                    row["node_type"] = "identity"
        report = self.analyze_changed_export(change)
        self.assertTrue(any("dependency requires" in e["reason"] for e in report["graph_exclusions"]))

    def test_duplicate_identity_quarantines_both_records(self) -> None:
        def change(export):
            duplicate = copy.deepcopy(next(row for row in export["records"] if row.get("id") == "ILL-PERMISSION"))
            duplicate["postcondition"] = "modify"
            export["records"].append(duplicate)
        report = self.analyze_changed_export(change)
        self.assertEqual([], report["supported_paths"])
        self.assertEqual(2, sum("duplicate record identifier" in q["reason"] for q in report["quarantine"]))
        self.assertEqual(report["reconciliation"]["raw"], sum(report["reconciliation"][key] for key in ("accepted", "quarantined", "rejected")))

    def test_legacy_attackpath_output_permissions_and_symlink_safety(self) -> None:
        cli_script = Path(__file__).resolve().parents[1] / "scripts/attackpath.py"
        fixture_input = FIXTURE / "input.json"
        with tempfile.TemporaryDirectory() as base_dir:
            base = Path(base_dir)
            out_dir = base / "reports"
            env = dict(os.environ, PYTHONPATH="", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
            res = subprocess.run([sys.executable, str(cli_script), "analyze", str(fixture_input),
                                  "--output-dir", str(out_dir)],
                                 capture_output=True, text=True, env=env)
            self.assertEqual(res.returncode, 0, f"CLI failed: {res.stderr}")
            self.assertEqual(stat.S_IMODE(out_dir.stat().st_mode), 0o700)
            for name in ("report.json", "graph.json", "report.md", "remediation-ledger.json"):
                f = out_dir / name
                self.assertTrue(f.exists(), f"missing report file: {name}")
                self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)

            # Pre-existing directory is rejected safely
            res_exists = subprocess.run([sys.executable, str(cli_script), "analyze", str(fixture_input),
                                         "--output-dir", str(out_dir)],
                                        capture_output=True, text=True, env=env)
            self.assertEqual(res_exists.returncode, 2)

            # Symlinked output target is rejected safely
            external_target = base / "external"
            external_target.mkdir()
            symlink_out = base / "symlink_dir"
            symlink_out.symlink_to(external_target)
            res_sym = subprocess.run([sys.executable, str(cli_script), "analyze", str(fixture_input),
                                      "--output-dir", str(symlink_out)],
                                     capture_output=True, text=True, env=env)
            self.assertEqual(res_sym.returncode, 2)
            self.assertEqual(list(external_target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
