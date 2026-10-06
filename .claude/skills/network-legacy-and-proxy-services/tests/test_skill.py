# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Tests for network-legacy-and-proxy-services contributor skill."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    CleanupReceipt,
    ExecutionEffect,
    LegacyAuthPrerequisite,
    LegacyCategory,
    LegacyExposureStatus,
    LegacyPrivilegeCandidate,
    LegacyPrivilegeImpact,
    LegacyServicesReport,
    LegacyServiceType,
    OfflineSyntheticLegacyCollector,
    assess_legacy_services,
)
from cops.discovery.cli import (
    command_legacy_discovery,
)


class TestNetworkLegacyAndProxyServicesSkill(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "vulnerable-legacy.corp.internal": {
                "ndmp": {
                    "auth_required": False,
                    "version": "NDMPv4",
                },
                "iscsi": {
                    "chap_enforced": False,
                    "targets": ["iqn.2026-10.corp.storage:lun01"],
                    "version": "iSCSI Target 2.1",
                },
                "ipmi": {
                    "cipher_zero": True,
                    "rakp_dumpable": True,
                    "version": "IPMI 2.0 (RMCP+)",
                },
                "cisco_smart_install": {
                    "smi_active": True,
                    "auth_required": False,
                    "version": "Cisco IOS 15.2",
                },
                "tacacs": {
                    "auth_required": False,
                    "single_connect": True,
                    "version": "TACACS+ 13.0",
                },
                "ike": {
                    "aggressive_mode": True,
                    "auth_required": False,
                    "transform": "3DES-SHA1-MODP1024",
                },
                "pptp": {
                    "mschapv2": True,
                    "auth_required": False,
                    "firmware": "Poptop 1.4.0",
                },
                "socks": {
                    "auth_required": False,
                    "egress_restricted": False,
                    "version": "SOCKS5",
                },
                "squid": {
                    "open_proxy": True,
                    "egress_restricted": False,
                    "version": "Squid 4.13",
                },
            },
            "hardened-legacy.corp.internal": {
                "ndmp": {
                    "protected": True,
                    "auth_required": True,
                    "version": "NDMPv4",
                },
                "iscsi": {
                    "protected": True,
                    "chap_enforced": True,
                    "version": "iSCSI Target 2.1",
                },
                "ipmi": {
                    "protected": True,
                    "cipher_zero_disabled": True,
                    "rakp_auth_enforced": True,
                    "version": "IPMI 2.0 (RMCP+)",
                },
                "cisco_smart_install": {
                    "protected": True,
                    "no_vstack": True,
                    "version": "Cisco IOS 15.2",
                },
                "tacacs": {
                    "protected": True,
                    "shared_key_enforced": True,
                    "tls_enabled": True,
                    "version": "TACACS+ 13.0",
                },
                "ike": {
                    "protected": True,
                    "ikev2_only": True,
                    "aggressive_mode_disabled": True,
                    "version": "StrongSwan 5.9",
                },
                "pptp": {
                    "protected": True,
                    "decommissioned": True,
                    "version": "Decommissioned",
                },
                "socks": {
                    "protected": True,
                    "auth_required": True,
                    "egress_restricted": True,
                    "version": "Dante SOCKS 1.4",
                },
                "squid": {
                    "protected": True,
                    "acl_enforced": True,
                    "egress_restricted": True,
                    "version": "Squid 5.7",
                },
            },
            "inaccessible.corp.internal": {
                "unreachable": True,
            },
        }

    def test_models_and_enums(self):
        """Verify full protocol, category, and finding model taxonomies."""
        self.assertEqual(len(LegacyServiceType), 9)
        self.assertEqual(len(LegacyCategory), 5)

        candidate = LegacyPrivilegeCandidate(
            candidate_id="priv-c0-01",
            service_type=LegacyServiceType.IPMI.value,
            category=LegacyCategory.OUT_OF_BAND_HARDWARE_MANAGEMENT.value,
            target_host="bmc01.corp.internal",
            port=623,
            finding_type="ipmi_cipher_zero_bypass",
            auth_prerequisites=LegacyAuthPrerequisite.CIPHER_ZERO.value,
            privilege_impact=LegacyPrivilegeImpact.HARDWARE_BMC_TAKEOVER.value,
            execution_effect=ExecutionEffect.CODE_EXECUTION.value,
        )
        self.assertTrue(candidate.evidence_hash)
        self.assertIn("Cipher 0", candidate.remediation_guidance)

        d = candidate.to_dict()
        rehydrated = LegacyPrivilegeCandidate.from_dict(d)
        self.assertEqual(candidate.candidate_id, rehydrated.candidate_id)
        self.assertEqual(candidate.evidence_hash, rehydrated.evidence_hash)

        receipt = CleanupReceipt(
            receipt_id="rec-01",
            target_host="bmc01.corp.internal",
            service_type="ipmi",
            artifact_type="canary_bmc_session",
            artifact_identifier="canary_bmc_01",
        )
        self.assertTrue(receipt.receipt_hash)
        self.assertEqual(receipt.action_taken, "verified_removed")
        self.assertTrue(receipt.verified_clean)

    def test_offline_synthetic_vulnerable_assessment(self):
        """Test assessment of all 9 protocols generating legacy privilege candidates."""
        collector = OfflineSyntheticLegacyCollector(
            targets=self.mock_services,
            allow_code_execution=True,
            allow_state_change=True,
        )
        report = assess_legacy_services(
            targets=["vulnerable-legacy.corp.internal"],
            collector=collector,
            vantage="internal",
            canary_id="canary_legacy_probe_01",
            allow_code_execution=True,
            allow_state_change=True,
        )

        self.assertEqual(report.total_probed, 9)
        self.assertEqual(report.total_exposed, 9)
        self.assertGreaterEqual(report.candidates_count, 9)
        self.assertGreaterEqual(report.cleanup_receipts_count, 9)

        # Check proxy egress testing
        socks_ass = next(a for a in report.assessments if a.service_type == "socks")
        self.assertTrue(socks_ass.proxy_egress_tested)
        self.assertFalse(socks_ass.proxy_egress_restricted)

        squid_ass = next(a for a in report.assessments if a.service_type == "squid")
        self.assertTrue(squid_ass.proxy_egress_tested)
        self.assertFalse(squid_ass.proxy_egress_restricted)

        # Check IPMI Cipher 0 code execution
        ipmi_ass = next(a for a in report.assessments if a.service_type == "ipmi")
        self.assertTrue(ipmi_ass.can_execute_code)

        # Check Cisco Smart Install code execution
        smi_ass = next(a for a in report.assessments if a.service_type == "cisco_smart_install")
        self.assertTrue(smi_ass.can_execute_code)

    def test_code_execution_gating_and_uncertainty(self):
        """Verify code execution is blocked without explicit authorization."""
        collector = OfflineSyntheticLegacyCollector(
            targets=self.mock_services,
            allow_code_execution=False,
            allow_state_change=False,
        )
        report = assess_legacy_services(
            targets=["vulnerable-legacy.corp.internal"],
            service_types=["ipmi", "cisco_smart_install"],
            collector=collector,
            allow_code_execution=False,
            allow_state_change=False,
        )

        for ass in report.assessments:
            self.assertFalse(ass.can_execute_code)
            self.assertTrue(any("Code execution verification skipped" in u for u in ass.uncertainty_notes))

    def test_offline_synthetic_hardened_assessment(self):
        """Test assessment of protected legacy services."""
        collector = OfflineSyntheticLegacyCollector(targets=self.mock_services)
        report = assess_legacy_services(
            targets=["hardened-legacy.corp.internal"],
            collector=collector,
            canary_id="canary_hardened_probe",
        )

        self.assertEqual(report.total_probed, 9)
        self.assertEqual(report.total_protected, 9)
        self.assertEqual(report.candidates_count, 0)
        self.assertEqual(report.cleanup_receipts_count, 9)

        # Protected proxies should have egress restricted
        socks_ass = next(a for a in report.assessments if a.service_type == "socks")
        self.assertTrue(socks_ass.proxy_egress_tested)
        self.assertTrue(socks_ass.proxy_egress_restricted)

        squid_ass = next(a for a in report.assessments if a.service_type == "squid")
        self.assertTrue(squid_ass.proxy_egress_tested)
        self.assertTrue(squid_ass.proxy_egress_restricted)

    def test_truth_boundary_inaccessible_never_protected(self):
        """Crucial truth boundary: Inaccessible targets must NEVER be reported as protected or secure."""
        collector = OfflineSyntheticLegacyCollector(targets=self.mock_services)
        report = assess_legacy_services(
            targets=["inaccessible.corp.internal"],
            collector=collector,
        )

        self.assertEqual(report.total_probed, 9)
        self.assertEqual(report.total_inaccessible, 9)
        self.assertEqual(report.total_protected, 0)
        self.assertEqual(report.candidates_count, 0)

        for ass in report.assessments:
            self.assertEqual(ass.exposure_status, LegacyExposureStatus.INACCESSIBLE.value)
            self.assertEqual(ass.auth_prerequisite, LegacyAuthPrerequisite.UNKNOWN.value)
            self.assertFalse(ass.canary_validated)
            self.assertTrue(any("cannot be reported as secure" in u for u in ass.uncertainty_notes))

    def test_report_serialization_and_persistence(self):
        """Test roundtrip JSON file persistence of LegacyServicesReport."""
        collector = OfflineSyntheticLegacyCollector(targets=self.mock_services)
        report = assess_legacy_services(
            targets=["vulnerable-legacy.corp.internal"],
            service_types=["ndmp", "socks"],
            collector=collector,
            canary_id="canary_test",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "legacy_report.json"
            report.save(file_path)
            self.assertTrue(file_path.is_file())

            loaded = LegacyServicesReport.load(file_path)
            self.assertEqual(report.report_id, loaded.report_id)
            self.assertEqual(report.total_probed, loaded.total_probed)
            self.assertEqual(report.candidates_count, loaded.candidates_count)
            self.assertEqual(len(loaded.assessments), 2)

    def test_cli_lifecycle(self):
        """Verify CLI subcommands: assess, candidates, cleanup, inspect."""
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            offline_targets_file = td / "targets.json"
            offline_targets_file.write_text(json.dumps(self.mock_services), encoding="utf-8")

            report_file = td / "report.json"
            candidates_file = td / "candidates.json"
            cleanup_file = td / "cleanup.json"

            # 1. assess
            args_assess = argparse.Namespace(
                legacy_command="assess",
                targets="vulnerable-legacy.corp.internal",
                services="ndmp,iscsi,ipmi,cisco_smart_install,tacacs,ike,pptp,socks,squid",
                vantage="internal",
                scope_ref="authorized-scope",
                canary_id="canary_cli_01",
                allow_code_execution=True,
                allow_state_change=True,
                mode="synthetic",
                offline_targets=str(offline_targets_file),
                output=str(report_file),
            )
            res = command_legacy_discovery(args_assess)
            self.assertEqual(res, 0)
            self.assertTrue(report_file.is_file())

            # 2. candidates
            args_cand = argparse.Namespace(
                legacy_command="candidates",
                report=str(report_file),
                output=str(candidates_file),
            )
            res = command_legacy_discovery(args_cand)
            self.assertEqual(res, 0)
            self.assertTrue(candidates_file.is_file())
            cand_data = json.loads(candidates_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(cand_data), 9)

            # 3. cleanup
            args_clean = argparse.Namespace(
                legacy_command="cleanup",
                report=str(report_file),
                output=str(cleanup_file),
            )
            res = command_legacy_discovery(args_clean)
            self.assertEqual(res, 0)
            self.assertTrue(cleanup_file.is_file())
            clean_data = json.loads(cleanup_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(clean_data), 9)
            self.assertTrue(all(r["action_taken"] == "verified_removed" for r in clean_data))

            # 4. inspect
            args_insp = argparse.Namespace(
                legacy_command="inspect",
                report=str(report_file),
                json=True,
            )
            res = command_legacy_discovery(args_insp)
            self.assertEqual(res, 0)


if __name__ == "__main__":
    unittest.main()
