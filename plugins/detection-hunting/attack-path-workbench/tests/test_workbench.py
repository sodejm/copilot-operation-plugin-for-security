"""Positive, denial, recovery, and deterministic-output controls."""

from __future__ import annotations

import contextlib
import copy
import errno
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

from attackpath import cli as cli_module
from attackpath.azure import report as azure_report
from attackpath.core import (
    GateError,
    analyze,
    audit_report,
    canonical,
    file_hash,
    load_json,
    query_intent,
    rank_paths,
    trace_paths,
    validate_input,
)
from attackpath.search import SearchLimits

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "illustrative"


class WorkbenchTests(unittest.TestCase):
    def assert_complete_legacy_report_set(self, output: Path) -> None:
        marker = json.loads((output / "completion.json").read_text())
        self.assertEqual("attackpath.completion/v1", marker["schema_version"])
        self.assertEqual("complete", marker["status"])
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["run"]["run_id"], marker["run_id"])
        self.assertEqual(set(cli_module.LEGACY_REPORT_FILES), set(marker["files"]))
        for name in cli_module.LEGACY_REPORT_FILES:
            self.assertEqual(
                hashlib.sha256((output / name).read_bytes()).hexdigest(),
                marker["files"][name],
            )

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
        nodes = {
            name: {
                "record": {"node_type": "asset"},
                "class": "observed",
                "evidence_id": f"N-{name}",
                "confidence": "high",
            }
            for name in ("A", "B", "C")
        }
        findings = [
            {
                "record": {"id": "F", "asset_ref": "A"},
                "class": "observed",
                "evidence_id": "E-F",
                "confidence": "high",
                "scope": "S",
            }
        ]
        edges = [
            {
                "record": {
                    "id": f"E-{target}",
                    "from": "A",
                    "to": target,
                    "relation": "reachable_from",
                    "preconditions": ["finding_on_asset"],
                    "postcondition": "network_reachability",
                    "support": "observed",
                },
                "evidence_id": f"E-{target}",
                "class": "observed",
                "confidence": "high",
            }
            for target in ("B", "C")
        ]
        crowns = [{"asset_ref": "B", "priority": 1}, {"asset_ref": "C", "priority": 2}]
        for overrides, targets, reason in (
            ({"frontier": 1}, crowns, "frontier_limit"),
            ({"complete_paths": 1}, crowns, "complete_path_limit"),
            ({"partial_paths": 1}, [], "partial_path_limit"),
        ):
            with self.subTest(reason=reason):
                _, _, receipt = trace_paths(nodes, findings, edges, targets, SearchLimits.from_values(overrides))
                self.assertEqual(reason, receipt["stop_reason"])
                self.assertFalse(receipt["complete"])
                self.assertEqual("best_discovered", receipt["ranking_scope"])

    def test_high_branch_search_is_bounded_repeatable_and_visibly_incomplete(self) -> None:
        width = 12
        depth = 5
        nodes = {
            "START": {
                "record": {"node_type": "asset"},
                "class": "observed",
                "evidence_id": "N-START",
                "confidence": "high",
            }
        }
        for layer in range(1, depth + 1):
            for index in range(width):
                name = f"L{layer}-{index:02d}"
                nodes[name] = {
                    "record": {"node_type": "asset"},
                    "class": "observed",
                    "evidence_id": f"N-{name}",
                    "confidence": "high",
                }
        findings = [
            {
                "record": {"id": "F-START", "asset_ref": "START"},
                "class": "observed",
                "evidence_id": "E-F-START",
                "confidence": "high",
                "scope": "SCOPE",
            }
        ]
        edges = []
        prior = ["START"]
        for layer in range(1, depth + 1):
            current = [f"L{layer}-{index:02d}" for index in range(width)]
            for source in prior:
                for target in current:
                    edge_id = f"E-{source}-{target}"
                    edges.append(
                        {
                            "record": {
                                "id": edge_id,
                                "from": source,
                                "to": target,
                                "relation": "reachable_from",
                                "preconditions": (
                                    ["finding_on_asset"] if source == "START" else ["network_reachability"]
                                ),
                                "postcondition": "network_reachability",
                                "support": "observed",
                            },
                            "evidence_id": edge_id,
                            "class": "observed",
                            "confidence": "high",
                        }
                    )
            prior = current
        crowns = [{"asset_ref": f"L{depth}-{index:02d}", "priority": index + 1} for index in range(width)]
        limits = SearchLimits.from_values(
            {"expansions": 600, "frontier": 1_000, "complete_paths": 1_000, "partial_paths": 1_000, "emitted_paths": 8}
        )

        # Fixture construction is intentionally outside both measurements. The peak cap
        # allows one 4 KiB page for every fixed graph item and permitted expansion. That
        # leaves headroom for Python object overhead while still catching retained queued
        # or discovered state that grows materially beyond the bounded search workload.
        memory_ceiling = 4 * 1024 * (len(nodes) + len(edges) + limits.expansions)
        tracemalloc.start()
        try:
            started = time.perf_counter()
            first = trace_paths(nodes, findings, edges, crowns, limits, max_depth=depth)
            search_seconds = time.perf_counter() - started
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        second = trace_paths(nodes, findings, edges, crowns, limits, max_depth=depth)

        paths, partial, receipt = first
        self.assertEqual(first, second)
        self.assertEqual(
            {"expansions": 600, "max_frontier": 56, "complete_paths": 547, "partial_paths": 0, "emitted_paths": 8},
            receipt["consumed"],
        )
        self.assertEqual("expansion_limit", receipt["stop_reason"])
        self.assertFalse(receipt["complete"])
        self.assertEqual("best_discovered", receipt["ranking_scope"])
        self.assertEqual([], partial)
        self.assertEqual(8, len(paths))
        self.assertLessEqual(search_seconds, 5.0)
        self.assertLessEqual(peak_bytes, memory_ceiling)
        self.assertTrue(all(path["target"] == f"L{depth}-00" for path in paths))
        self.assertEqual(
            [
                (
                    "P-02847eeae0883daf",
                    ["E-START-L1-00", "E-L1-00-L2-00", "E-L2-00-L3-00", "E-L3-00-L4-09", "E-L4-09-L5-00"],
                ),
                (
                    "P-1a31062c62b8f6a5",
                    ["E-START-L1-00", "E-L1-00-L2-00", "E-L2-00-L3-03", "E-L3-03-L4-01", "E-L4-01-L5-00"],
                ),
                (
                    "P-1e9ad07a7a67ca9b",
                    ["E-START-L1-00", "E-L1-00-L2-00", "E-L2-00-L3-00", "E-L3-00-L4-05", "E-L4-05-L5-00"],
                ),
            ],
            [(path["path_id"], [step["edge_id"] for step in path["steps"]]) for path in paths[:3]],
        )
        self.assertEqual(
            [
                {
                    "crown_priority": 1,
                    "business_rating": "unrated",
                    "supported_step_count": depth,
                    "total_step_count": depth,
                }
            ]
            * 3,
            [path["rank_inputs"] for path in paths[:3]],
        )

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
            export["records"].append(
                {
                    "record_type": "node",
                    "id": "ILL-DEAD-END",
                    "node_type": "asset",
                    "scope": "ILL-SCOPE",
                    "observed_at": "2026-01-01T00:00:00Z",
                    "support": "observed",
                }
            )
            export["records"].append(
                {
                    "record_type": "edge",
                    "id": "ILL-DEAD-END-EDGE",
                    "from": "ILL-ASSET-A",
                    "to": "ILL-DEAD-END",
                    "relation": "reachable_from",
                    "preconditions": ["finding_on_asset"],
                    "postcondition": "network_reachability",
                    "scope": "ILL-SCOPE",
                    "observed_at": "2026-01-01T00:00:00Z",
                    "support": "observed",
                }
            )

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
        self.assertEqual(
            report["reconciliation"]["raw"],
            sum(report["reconciliation"][key] for key in ("accepted", "quarantined", "rejected")),
        )

    def test_legacy_attackpath_output_permissions_and_symlink_safety(self) -> None:
        cli_script = Path(__file__).resolve().parents[1] / "scripts/attackpath.py"
        fixture_input = FIXTURE / "input.json"
        with tempfile.TemporaryDirectory() as base_dir:
            base = Path(base_dir)
            out_dir = base / "reports"
            env = dict(os.environ, PYTHONPATH="", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
            res = subprocess.run(
                [sys.executable, str(cli_script), "analyze", str(fixture_input), "--output-dir", str(out_dir)],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res.returncode, 0, f"CLI failed: {res.stderr}")
            self.assertEqual(stat.S_IMODE(out_dir.stat().st_mode), 0o700)
            for name in (*cli_module.LEGACY_REPORT_FILES, "completion.json"):
                f = out_dir / name
                self.assertTrue(f.exists(), f"missing report file: {name}")
                self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
            self.assert_complete_legacy_report_set(out_dir)

            # Pre-existing directory is rejected safely
            res_exists = subprocess.run(
                [sys.executable, str(cli_script), "analyze", str(fixture_input), "--output-dir", str(out_dir)],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res_exists.returncode, 2)

            # Symlinked output target is rejected safely
            external_target = base / "external"
            external_target.mkdir()
            symlink_out = base / "symlink_dir"
            symlink_out.symlink_to(external_target)
            res_sym = subprocess.run(
                [sys.executable, str(cli_script), "analyze", str(fixture_input), "--output-dir", str(symlink_out)],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res_sym.returncode, 2)
            self.assertEqual(list(external_target.iterdir()), [])

    def test_legacy_output_parent_swap_is_contained_and_not_complete(self) -> None:
        with tempfile.TemporaryDirectory() as base_dir:
            base = Path(base_dir)
            selected_parent = base / "selected"
            selected_parent.mkdir()
            moved_parent = base / "moved"
            external = base / "external"
            external.mkdir()
            output = selected_parent / "reports"
            write_ready = threading.Event()
            swapped = threading.Event()
            swap_errors = []
            real_open = os.open

            def synchronized_open(path, flags, mode=0o777, *, dir_fd=None):
                if path == "report.json" and dir_fd is not None:
                    write_ready.set()
                    if not swapped.wait(5):
                        raise OSError(errno.ETIMEDOUT, "parent swap did not run")
                kwargs = {} if dir_fd is None else {"dir_fd": dir_fd}
                return real_open(path, flags, mode, **kwargs)

            def swap_parent():
                if not write_ready.wait(5):
                    swap_errors.append("writer did not reach report.json")
                else:
                    selected_parent.rename(moved_parent)
                    selected_parent.symlink_to(external, target_is_directory=True)
                swapped.set()

            swap_thread = threading.Thread(target=swap_parent)
            swap_thread.start()
            stdout = io.StringIO()
            stderr = io.StringIO()
            supported_dir_fd = azure_report.os.supports_dir_fd | {synchronized_open}
            with (
                mock.patch.object(azure_report.os, "open", synchronized_open),
                mock.patch.object(azure_report.os, "supports_dir_fd", supported_dir_fd),
            ):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = cli_module.main(
                        [
                            "analyze",
                            str(FIXTURE / "input.json"),
                            "--output-dir",
                            str(output),
                        ]
                    )
            swap_thread.join(5)

            self.assertFalse(swap_thread.is_alive())
            self.assertEqual([], swap_errors)
            self.assertEqual(2, result)
            self.assertEqual("", stdout.getvalue())
            contained = moved_parent / "reports"
            self.assertEqual(set(cli_module.LEGACY_REPORT_FILES), {path.name for path in contained.iterdir()})
            self.assertFalse((contained / "completion.json").exists())
            self.assertEqual([], list(external.iterdir()))

    def test_output_path_revalidation_rejects_midwalk_ancestor_swap(self) -> None:
        with tempfile.TemporaryDirectory() as base_dir:
            base = Path(base_dir)
            selected = base / "selected"
            output = selected / "reports"
            selected.mkdir()
            output.mkdir()
            moved = base / "moved"
            external = base / "external"
            external.mkdir()
            directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
            real_open = os.open
            swapped = False

            def swap_during_walk(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if path == "reports" and dir_fd is not None and not swapped:
                    selected.rename(moved)
                    selected.symlink_to(external, target_is_directory=True)
                    swapped = True
                kwargs = {} if dir_fd is None else {"dir_fd": dir_fd}
                return real_open(path, flags, mode, **kwargs)

            try:
                with mock.patch.object(azure_report.os, "open", swap_during_walk):
                    with self.assertRaises(OSError):
                        azure_report._path_names_directory(azure_report.absolute_parts(output), directory)
            finally:
                os.close(directory)

            self.assertTrue(swapped)

    def test_legacy_report_write_failures_never_complete(self) -> None:
        real_open = os.open
        real_write = os.write
        for index, failed_name in enumerate(cli_module.LEGACY_REPORT_FILES):
            with self.subTest(failed_name=failed_name), tempfile.TemporaryDirectory() as base_dir:
                output = Path(base_dir) / "reports"
                failed_descriptors = set()

                def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
                    kwargs = {} if dir_fd is None else {"dir_fd": dir_fd}
                    descriptor = real_open(path, flags, mode, **kwargs)
                    if path == failed_name and dir_fd is not None:
                        failed_descriptors.add(descriptor)
                    return descriptor

                def failing_write(descriptor, data):
                    if descriptor in failed_descriptors:
                        raise OSError(errno.ENOSPC, "injected report write failure")
                    return real_write(descriptor, data)

                stdout = io.StringIO()
                stderr = io.StringIO()
                supported_dir_fd = azure_report.os.supports_dir_fd | {tracked_open}
                with (
                    mock.patch.object(azure_report.os, "open", tracked_open),
                    mock.patch.object(azure_report.os, "supports_dir_fd", supported_dir_fd),
                    mock.patch.object(azure_report.os, "write", failing_write),
                ):
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        result = cli_module.main(
                            [
                                "analyze",
                                str(FIXTURE / "input.json"),
                                "--output-dir",
                                str(output),
                            ]
                        )

                self.assertEqual(2, result)
                self.assertEqual("", stdout.getvalue())
                self.assertFalse((output / "completion.json").exists())
                self.assertEqual(
                    set(cli_module.LEGACY_REPORT_FILES[: index + 1]),
                    {path.name for path in output.iterdir()},
                )

    def test_writer_preserves_completion_marker_on_report_collision(self) -> None:
        real_open = os.open
        real_write = os.write
        foreign_marker = b'{"owner":"concurrent-writer"}\n'
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = b'{"status":"complete"}\n'

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"
            injected = False

            def collision_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal injected
                kwargs = {} if dir_fd is None else {"dir_fd": dir_fd}
                if path == "report.json" and dir_fd is not None and not injected:
                    injected = True
                    marker_fd = real_open(
                        "completion.json",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=dir_fd,
                    )
                    try:
                        real_write(marker_fd, foreign_marker)
                    finally:
                        os.close(marker_fd)
                    collision_fd = real_open(
                        path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=dir_fd,
                    )
                    os.close(collision_fd)
                return real_open(path, flags, mode, **kwargs)

            supported_dir_fd = azure_report.os.supports_dir_fd | {collision_open}
            with (
                mock.patch.object(azure_report.os, "open", collision_open),
                mock.patch.object(azure_report.os, "supports_dir_fd", supported_dir_fd),
            ):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            self.assertTrue(injected)
            self.assertEqual(foreign_marker, (output / "completion.json").read_bytes())

    def test_writer_preserves_completion_marker_at_publication_collision(self) -> None:
        real_publish = azure_report._publish_completion
        real_open = os.open
        real_write = os.write
        foreign_marker = b'{"owner":"replacement-writer"}\n'
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = b'{"status":"complete"}\n'

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"
            injected = False

            def collision_publish(staging_fd, directory):
                nonlocal injected
                if not injected:
                    injected = True
                    marker_fd = real_open(
                        "completion.json",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                    try:
                        real_write(marker_fd, foreign_marker)
                    finally:
                        os.close(marker_fd)
                return real_publish(staging_fd, directory)

            with mock.patch.object(azure_report, "_publish_completion", collision_publish):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            self.assertTrue(injected)
            self.assertEqual(foreign_marker, (output / "completion.json").read_bytes())

    def test_writer_syncs_report_directory_before_publishing_completion(self) -> None:
        real_fsync = os.fsync
        real_open = os.open
        real_publish = azure_report._publish_completion
        events = []
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = b'{"status":"complete"}\n'

        def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
            if isinstance(path, str) and path.startswith(".completion-"):
                events.append("marker-open")
            kwargs = {} if dir_fd is None else {"dir_fd": dir_fd}
            return real_open(path, flags, mode, **kwargs)

        def tracked_fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                events.append("directory-fsync")
            return real_fsync(descriptor)

        def tracked_publish(staging_fd, directory):
            events.append("publish")
            return real_publish(staging_fd, directory)

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"
            supported_dir_fd = azure_report.os.supports_dir_fd | {tracked_open}
            with (
                mock.patch.object(azure_report.os, "open", tracked_open),
                mock.patch.object(azure_report.os, "fsync", tracked_fsync),
                mock.patch.object(azure_report.os, "supports_dir_fd", supported_dir_fd),
                mock.patch.object(azure_report, "_publish_completion", tracked_publish),
            ):
                azure_report.write_files(output, contents, 4096)

            marker_open_index = events.index("marker-open")
            publish_index = events.index("publish")
            self.assertEqual("directory-fsync", events[marker_open_index - 1])
            self.assertEqual("directory-fsync", events[publish_index + 1])
            self.assertGreaterEqual(events[:publish_index].count("directory-fsync"), 3)

    def test_writer_directory_sync_failure_never_publishes_completion(self) -> None:
        real_fsync = os.fsync
        directory_syncs = 0
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = b'{"status":"complete"}\n'

        def failing_fsync(descriptor):
            nonlocal directory_syncs
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                directory_syncs += 1
                if directory_syncs == 2:
                    raise OSError(errno.EIO, "injected directory sync failure")
            return real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"
            with mock.patch.object(azure_report.os, "fsync", failing_fsync):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            self.assertEqual(set(cli_module.LEGACY_REPORT_FILES), {path.name for path in output.iterdir()})

    def test_writer_parent_sync_failure_never_publishes_completion(self) -> None:
        real_fsync = os.fsync
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = b'{"status":"complete"}\n'

        with tempfile.TemporaryDirectory() as base_dir:
            parent = Path(base_dir)
            output = parent / "reports"
            parent_identity = (parent.stat().st_dev, parent.stat().st_ino)

            def failing_fsync(descriptor):
                item = os.fstat(descriptor)
                if stat.S_ISDIR(item.st_mode) and (item.st_dev, item.st_ino) == parent_identity:
                    raise OSError(errno.EIO, "injected parent sync failure")
                return real_fsync(descriptor)

            with (
                mock.patch.object(azure_report.os, "fsync", failing_fsync),
                mock.patch.object(azure_report, "_publish_completion") as publish,
            ):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            publish.assert_not_called()
            self.assertEqual([], list(output.iterdir()))

    def test_writer_publishes_open_staging_inode_after_path_substitution(self) -> None:
        real_publish = azure_report._publish_completion
        completion = b'{"status":"complete"}\n'
        foreign = b'{"owner":"replacement"}\n'
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = completion
        token = "ab" * 16
        staging_name = f".completion-{token}.tmp"

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"

            def substitute_then_publish(staging_fd, directory):
                os.rename(staging_name, ".captured-completion.tmp", src_dir_fd=directory, dst_dir_fd=directory)
                replacement = os.open(
                    staging_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                try:
                    os.write(replacement, foreign)
                finally:
                    os.close(replacement)
                return real_publish(staging_fd, directory)

            with (
                mock.patch.object(azure_report.secrets, "token_hex", return_value=token),
                mock.patch.object(azure_report, "_publish_completion", substitute_then_publish),
            ):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            self.assertEqual(completion, (output / "completion.json").read_bytes())
            self.assertEqual(foreign, (output / staging_name).read_bytes())
            self.assertEqual(completion, (output / ".captured-completion.tmp").read_bytes())

    def test_writer_removes_staging_file_after_prepublication_write_failure(self) -> None:
        real_open = os.open
        real_write = os.write
        staging_descriptors = set()
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = b'{"status":"complete"}\n'

        def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
            kwargs = {} if dir_fd is None else {"dir_fd": dir_fd}
            descriptor = real_open(path, flags, mode, **kwargs)
            if isinstance(path, str) and path.startswith(".completion-"):
                staging_descriptors.add(descriptor)
            return descriptor

        def failing_write(descriptor, data):
            if descriptor in staging_descriptors:
                raise OSError(errno.ENOSPC, "injected completion staging write failure")
            return real_write(descriptor, data)

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"
            supported_dir_fd = azure_report.os.supports_dir_fd | {tracked_open}
            with (
                mock.patch.object(azure_report.os, "open", tracked_open),
                mock.patch.object(azure_report.os, "supports_dir_fd", supported_dir_fd),
                mock.patch.object(azure_report.os, "write", failing_write),
            ):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            self.assertEqual(set(cli_module.LEGACY_REPORT_FILES), {path.name for path in output.iterdir()})

    def test_writer_keeps_published_completion_after_staging_cleanup_failure(self) -> None:
        real_fsync = os.fsync
        real_unlink = os.unlink
        real_publish = azure_report._publish_completion
        marker_synced = False
        published = False
        completion = b'{"status":"complete"}\n'
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        contents["completion.json"] = completion

        def tracked_publish(staging_fd, directory):
            nonlocal published
            result = real_publish(staging_fd, directory)
            published = True
            return result

        def tracked_fsync(descriptor):
            nonlocal marker_synced
            result = real_fsync(descriptor)
            if published and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                marker_synced = True
            return result

        def failing_unlink(path, *, dir_fd=None):
            if isinstance(path, str) and path.startswith(".completion-"):
                self.assertTrue(marker_synced)
                raise OSError(errno.EIO, "injected staging cleanup failure")
            return real_unlink(path, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"
            with (
                mock.patch.object(azure_report, "_publish_completion", tracked_publish),
                mock.patch.object(azure_report.os, "fsync", tracked_fsync),
                mock.patch.object(azure_report.os, "unlink", failing_unlink),
            ):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            self.assertTrue(marker_synced)
            self.assertEqual(completion, (output / "completion.json").read_bytes())
            self.assertEqual(1, len(list(output.glob(".completion-*.tmp"))))

    def test_writer_keeps_visible_completion_after_postpublication_sync_failure(self) -> None:
        real_fsync = os.fsync
        real_publish = azure_report._publish_completion
        published = False
        contents = {name: (name + "\n").encode("utf-8") for name in cli_module.LEGACY_REPORT_FILES}
        completion = b'{"status":"complete"}\n'
        contents["completion.json"] = completion

        def failing_fsync(descriptor):
            if published and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "injected final directory sync failure")
            return real_fsync(descriptor)

        def tracked_publish(staging_fd, directory):
            nonlocal published
            result = real_publish(staging_fd, directory)
            published = True
            return result

        with tempfile.TemporaryDirectory() as base_dir:
            output = Path(base_dir) / "reports"
            with (
                mock.patch.object(azure_report.os, "fsync", failing_fsync),
                mock.patch.object(azure_report, "_publish_completion", tracked_publish),
            ):
                with self.assertRaises(azure_report.AzureError):
                    azure_report.write_files(output, contents, 4096)

            self.assertTrue(published)
            self.assertEqual(completion, (output / "completion.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
