"""Behavioral gates for the synthetic, entirely local assessment workflow."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from attack_surface_planner.core import GateError, analyze, canonical  # noqa: E402

FIXTURE = PACKAGE / "fixtures/synthetic"


class PlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(FIXTURE, self.root / "fixture")
        self.root = self.root / "fixture"
        self.manifest_path = self.root / "scope.json"

    def manifest(self) -> dict:
        return json.loads(self.manifest_path.read_text())

    def save_manifest(self, manifest: dict) -> None:
        self.manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")

    def update_source(self, manifest: dict, kind: str, records: list[dict]) -> None:
        source = next(item for item in manifest["sources"] if item["kind"] == kind)
        data = (json.dumps({"records": records}, sort_keys=True) + "\n").encode()
        (self.root / source["path"]).write_bytes(data)
        source["sha256"] = hashlib.sha256(data).hexdigest()
        source["record_count"] = len(records)
        self.save_manifest(manifest)

    def test_scoped_report_has_provenance_and_only_passive_proposals(self) -> None:
        report = analyze(self.manifest_path)
        self.assertEqual(report["summary"], {"in_scope": 4, "excluded": 3, "unresolved": 1})
        self.assertEqual(len(report["test_plan"]), 4)
        included = {item["asset_id"] for item in report["surface_map"]
                    if item["decision"] == "in_scope"}
        self.assertEqual({item["asset_id"] for item in report["test_plan"]}, included)
        for item in report["surface_map"]:
            self.assertEqual(item["evidence"]["confidence"], "reported-export")
            for field in ("source_kind", "source_file", "source_ref", "source_sha256",
                          "collected_at", "pointer"):
                self.assertTrue(item["evidence"][field])
        for item in report["test_plan"]:
            self.assertEqual(item["authorization"]["allowed_method"], "passive-review")
            for field in ("hypothesis", "method", "expected_observation", "expected_telemetry",
                          "stop_condition", "cleanup"):
                self.assertTrue(item[field])
        self.assertIn("api.evil-example.test", {item["identity"] for item in
                      report["surface_map"] if item["decision"] == "excluded"})
        self.assertIn("unknown.example.test", {item["identity"] for item in
                      report["surface_map"] if item["decision"] == "unresolved"})

    def test_deterministic_without_network(self) -> None:
        with patch.object(socket, "socket", side_effect=AssertionError("network attempted")), \
             patch.object(socket, "create_connection", side_effect=AssertionError("network attempted")):
            first = canonical(analyze(self.manifest_path))
            second = canonical(analyze(self.manifest_path))
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["network_requests"], 0)

    def test_active_mode_and_missing_approval_fail_closed(self) -> None:
        manifest = self.manifest()
        manifest["mode"] = "active"
        self.save_manifest(manifest)
        with self.assertRaisesRegex(GateError, "offline mode"):
            analyze(self.manifest_path)
        manifest["mode"] = "offline"
        del manifest["approval"]
        self.save_manifest(manifest)
        with self.assertRaisesRegex(GateError, "approval"):
            analyze(self.manifest_path)

    def test_subsecond_time_window_order(self) -> None:
        manifest = self.manifest()
        window = manifest["scope"]["time_windows"][0]
        window["start"] = "2026-09-30T12:00:00Z"
        window["end"] = "2026-09-30T12:00:00.500Z"
        self.save_manifest(manifest)
        self.assertEqual(len(analyze(self.manifest_path)["test_plan"]), 4)
        window["start"], window["end"] = window["end"], window["start"]
        self.save_manifest(manifest)
        with self.assertRaisesRegex(GateError, "window end must follow start"):
            analyze(self.manifest_path)

    def test_source_integrity_and_record_count_fail_closed(self) -> None:
        manifest = self.manifest()
        manifest["sources"][0]["sha256"] = "0" * 64
        self.save_manifest(manifest)
        with self.assertRaisesRegex(GateError, "SHA-256 mismatch"):
            analyze(self.manifest_path)
        manifest = self.manifest()
        manifest["sources"][0]["sha256"] = hashlib.sha256(
            (self.root / manifest["sources"][0]["path"]).read_bytes()).hexdigest()
        manifest["sources"][0]["record_count"] = 1
        self.save_manifest(manifest)
        with self.assertRaisesRegex(GateError, "record count mismatch"):
            analyze(self.manifest_path)

    def test_path_traversal_and_symlink_fail_closed(self) -> None:
        manifest = self.manifest()
        manifest["sources"][0]["path"] = "../outside.json"
        self.save_manifest(manifest)
        with self.assertRaisesRegex(GateError, "traversal-free"):
            analyze(self.manifest_path)
        manifest = self.manifest()
        manifest["sources"][0]["path"] = "linked.json"
        (self.root / "linked.json").symlink_to(self.root / "azure_resource_graph.json")
        self.save_manifest(manifest)
        with self.assertRaisesRegex(GateError, "safely opened"):
            analyze(self.manifest_path)

    def test_unapproved_ip_and_malformed_url_are_not_planned(self) -> None:
        manifest = self.manifest()
        records = [{"url": "https://admin.example.test/", "ip": "198.51.100.4",
                    "environment": "lab", "owner": "security-team"},
                   {"url": "https://unknown.example.test/?secret=redacted",
                    "environment": "lab", "owner": "security-team"}]
        self.update_source(manifest, "public_endpoint", records)
        report = analyze(self.manifest_path)
        endpoints = [item for item in report["surface_map"] if item["kind"] == "public_endpoint"]
        self.assertEqual({item["decision"] for item in endpoints}, {"excluded", "unresolved"})
        self.assertFalse(any(item["kind"] == "public_endpoint" and item["decision"] == "in_scope"
                             for item in report["surface_map"]))
        self.assertNotIn("secret", canonical(report))

    def test_explicit_exclusion_wins_over_allowlist(self) -> None:
        manifest = self.manifest()
        manifest["scope"]["exclusions"]["domains"].append("admin.example.test")
        self.save_manifest(manifest)
        report = analyze(self.manifest_path)
        endpoint = next(item for item in report["surface_map"] if item.get("identity") ==
                        "admin.example.test")
        self.assertEqual(endpoint["decision"], "excluded")
        self.assertIn("explicitly excluded", endpoint["reason"])

    def test_conflicting_azure_subscription_and_invalid_endpoint_port_remain_unresolved(self) -> None:
        manifest = self.manifest()
        azure = json.loads((self.root / "azure_resource_graph.json").read_text())["records"]
        azure[0]["subscription_id"] = "sub-999"
        self.update_source(manifest, "azure_resource_graph", azure)
        endpoint = [{"url": "https://admin.example.test:invalid/", "environment": "lab",
                     "owner": "security-team"}]
        self.update_source(manifest, "public_endpoint", endpoint)
        report = analyze(self.manifest_path)
        self.assertTrue(all(item["decision"] == "unresolved" for item in report["surface_map"]
                            if item["kind"] == "public_endpoint"))
        self.assertTrue(any(item["decision"] == "unresolved" for item in report["surface_map"]
                            if item["kind"] == "azure_resource_graph"))


if __name__ == "__main__":
    unittest.main()
