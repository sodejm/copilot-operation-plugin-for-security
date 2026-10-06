"""Unit and regression tests for COPS MITRE ATT&CK coverage and Attack Flow engine."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from cops.cli import main
from cops.coverage import (
    evaluate_coverage_gaps,
    generate_attack_flow,
    generate_coverage_matrix,
    load_attack_coverage,
    load_attack_reference,
    render_gap_report_markdown,
    review_coverage_freshness,
    validate_coverage_catalog,
)

ROOT = Path(__file__).resolve().parents[1]


class AttackCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reference = load_attack_reference(root=ROOT)
        self.catalog_path = ROOT / "catalog" / "attack_coverage.json"
        self.raw_catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        self.mappings = load_attack_coverage(root=ROOT)

    def test_reference_catalog_validity(self) -> None:
        self.assertEqual("cops.attack-reference/v1", self.reference.schema_version)
        self.assertEqual("18.0", self.reference.attck_version)
        self.assertTrue(self.reference.license)
        self.assertTrue(self.reference.copyright)
        self.assertTrue(self.reference.attribution)
        self.assertIn("T1110.003", self.reference.techniques)
        self.assertIn("T1078", self.reference.techniques)
        self.assertIn("T1086", self.reference.techniques)
        self.assertTrue(self.reference.techniques["T1086"].revoked)
        self.assertEqual("T1059.001", self.reference.techniques["T1086"].revoked_by)
        self.assertTrue(self.reference.techniques["T1064"].deprecated)

    def test_canonical_coverage_catalog_validity(self) -> None:
        errors = validate_coverage_catalog(self.raw_catalog, self.reference, root=ROOT, strict_reviews=True)
        self.assertEqual([], errors)
        self.assertGreater(len(self.mappings), 0)

    def test_schema_distinguishes_coverage_roles(self) -> None:
        roles = {m.coverage_role for m in self.mappings}
        self.assertIn("detection", roles)
        self.assertIn("investigation", roles)
        self.assertIn("prevention", roles)
        self.assertIn("response", roles)

        bad_catalog = copy.deepcopy(self.raw_catalog)
        bad_catalog["mappings"][0]["coverage_role"] = "remediation_actor"
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("invalid coverage_role" in err for err in errors))

    def test_rejected_on_revoked_technique(self) -> None:
        bad_catalog = copy.deepcopy(self.raw_catalog)
        bad_catalog["mappings"][0]["technique_id"] = "T1086"  # Revoked PowerShell
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("revoked technique 'T1086'" in err and "revoked by T1059.001" in err for err in errors))

    def test_rejected_on_deprecated_technique(self) -> None:
        bad_catalog = copy.deepcopy(self.raw_catalog)
        bad_catalog["mappings"][0]["technique_id"] = "T1064"  # Deprecated Scripting
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT, strict_reviews=True)
        self.assertTrue(any("deprecated technique 'T1064'" in err for err in errors))

    def test_rejected_on_attck_version_mismatch(self) -> None:
        bad_catalog = copy.deepcopy(self.raw_catalog)
        bad_catalog["attck_version"] = "17.0"
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("does not match pinned reference version" in err for err in errors))

        bad_catalog_item = copy.deepcopy(self.raw_catalog)
        bad_catalog_item["mappings"][0]["attck_version"] = "17.0"
        errors = validate_coverage_catalog(bad_catalog_item, self.reference, root=ROOT)
        self.assertTrue(any("attck_version '17.0' does not match catalog version" in err for err in errors))

    def test_rejected_on_duplicate_mapping_id(self) -> None:
        bad_catalog = copy.deepcopy(self.raw_catalog)
        bad_catalog["mappings"].append(copy.deepcopy(bad_catalog["mappings"][0]))
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("duplicate mapping_id" in err for err in errors))

    def test_rejected_on_duplicate_capability_technique(self) -> None:
        bad_catalog = copy.deepcopy(self.raw_catalog)
        dup = copy.deepcopy(bad_catalog["mappings"][0])
        dup["mapping_id"] = "COPS-COV-DUP-01"
        bad_catalog["mappings"].append(dup)
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("duplicates mapping for capability" in err for err in errors))

    def test_rejected_on_incomplete_evidence(self) -> None:
        bad_catalog = copy.deepcopy(self.raw_catalog)
        bad_catalog["mappings"][0]["evidence_sources"][0]["required_fields"] = []
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("required_fields must be a non-empty list" in err for err in errors))

    def test_validated_analytic_requires_fixture(self) -> None:
        bad_catalog = copy.deepcopy(self.raw_catalog)
        bad_catalog["mappings"][0]["validation_state"] = "validated"
        bad_catalog["mappings"][0]["validation_fixture"] = None
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("lacks required 'validation_fixture'" in err for err in errors))

        bad_catalog["mappings"][0]["validation_fixture"] = "nonexistent/fixture/path.py"
        errors = validate_coverage_catalog(bad_catalog, self.reference, root=ROOT)
        self.assertTrue(any("validation_fixture path does not exist" in err for err in errors))

    def test_matrix_distinguishes_validated_from_unverified(self) -> None:
        matrix = generate_coverage_matrix(self.mappings, self.reference)
        self.assertIn("**Validated**", matrix)
        self.assertIn("*Unverified (Draft)*", matrix)
        self.assertIn("H-PREVIEW-STORAGE", matrix)
        self.assertIn("Data from Cloud Storage", matrix)
        # Ensure preview/unverified analytic is marked as unverified
        for line in matrix.splitlines():
            if "H-PREVIEW-STORAGE" in line:
                self.assertIn("*Unverified (Draft)*", line)
                self.assertNotIn("**Validated**", line)

    def test_gap_analysis_separates_telemetry_from_analytics(self) -> None:
        env = {
            "available_products": ["Sentinel", "Entra ID"],
            "onboarded_sources": {
                "Sentinel:SigninLogs": ["TimeGenerated", "UserPrincipalName"],  # Missing ResultType for H01
            },
        }

        gaps = evaluate_coverage_gaps(self.mappings, self.reference, environment_profile=env)
        self.assertIn("telemetry_gaps", gaps)
        self.assertIn("analytics_gaps", gaps)
        self.assertIn("validated_coverage", gaps)

        # Check required_fields_missing
        missing_fields = [
            g for g in gaps["telemetry_gaps"]
            if g["category"] == "required_fields_missing" and g["technique_id"] == "T1110.003"
        ]
        self.assertGreater(len(missing_fields), 0)
        self.assertIn("missing required fields", missing_fields[0]["details"])

        # Check no_data_source (when product not in available_products)
        no_sources = [g for g in gaps["telemetry_gaps"] if g["category"] == "no_data_source"]
        self.assertGreater(len(no_sources), 0)

        # Check analytic_absent
        absent_analytics = [g for g in gaps["analytics_gaps"] if g["category"] == "analytic_absent"]
        self.assertGreater(len(absent_analytics), 0)

        # Check markdown rendering
        report = render_gap_report_markdown(gaps)
        self.assertIn("# COPS ATT&CK Gap Analysis Report", report)
        self.assertIn("## Telemetry Gaps", report)
        self.assertIn("## Analytics Gaps", report)

    def test_attack_flow_export_azure_identity(self) -> None:
        flow = generate_attack_flow("azure-identity", self.mappings, self.reference)
        self.assertEqual("bundle", flow["type"])
        self.assertEqual("2.1", flow["spec_version"])

        actions = [o for o in flow["objects"] if o["type"] == "attack-action"]
        self.assertGreaterEqual(len(actions), 5)

        # Check execution ordering
        orders = [a["execution_order"] for a in actions]
        self.assertEqual([1, 2, 3, 4, 4], orders)

        # Check technique IDs
        techniques = [a["technique_id"] for a in actions]
        self.assertEqual(["T1110.003", "T1078.004", "T1098.003", "T1098", "T1530"], techniques)

        # Check evidence references
        for a in actions:
            self.assertTrue(a["evidence_refs"])
            self.assertTrue(a["capability_refs"])

        # Check branching: two distinct actions at execution_order 4 sharing prerequisite condition
        branch_actions = [a for a in actions if a["execution_order"] == 4]
        self.assertEqual(2, len(branch_actions))
        self.assertEqual(branch_actions[0]["prerequisite_refs"], branch_actions[1]["prerequisite_refs"])

    def test_attack_flow_export_m365_compromise(self) -> None:
        flow = generate_attack_flow("m365-compromise", self.mappings, self.reference)
        self.assertEqual("bundle", flow["type"])
        self.assertEqual("2.1", flow["spec_version"])

        actions = [o for o in flow["objects"] if o["type"] == "attack-action"]
        self.assertEqual(4, len(actions))
        orders = [a["execution_order"] for a in actions]
        self.assertEqual([1, 2, 3, 3], orders)

        techniques = [a["technique_id"] for a in actions]
        self.assertEqual(["T1566.002", "T1078", "T1114.003", "T1213.002"], techniques)

    def test_freshness_review_clean(self) -> None:
        freshness = review_coverage_freshness(self.mappings, self.reference)
        self.assertEqual("fresh", freshness["status"])
        self.assertEqual(0, freshness["revoked_count"])
        self.assertEqual(0, freshness["deprecated_count"])

    def test_cli_coverage_matrix_and_check(self) -> None:
        # CLI check
        code = main(["coverage", "--check"], root=ROOT)
        self.assertEqual(0, code)

        # CLI matrix to temp file
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "matrix.md"
            code = main(["coverage", "--matrix", "--output", str(out_file)], root=ROOT)
            self.assertEqual(0, code)
            self.assertTrue(out_file.is_file())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("# COPS MITRE ATT&CK Coverage Matrix", content)

    def test_cli_coverage_gaps(self) -> None:
        code = main(["coverage", "--gaps"], root=ROOT)
        self.assertEqual(0, code)

    def test_cli_coverage_export_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "flow.json"
            code = main(["coverage", "--export-flow", "azure-identity", "--output-flow", str(out_file)], root=ROOT)
            self.assertEqual(0, code)
            self.assertTrue(out_file.is_file())
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual("bundle", data["type"])
            self.assertEqual("2.1", data["spec_version"])


if __name__ == "__main__":
    unittest.main()
