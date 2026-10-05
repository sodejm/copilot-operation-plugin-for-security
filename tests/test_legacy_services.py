"""Unit, contract, and CLI tests for legacy enterprise, management, and proxy services assessment."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    CleanupReceipt,
    DEFAULT_LEGACY_PORTS,
    ExecutionEffect,
    LegacyAuthPrerequisite,
    LegacyCategory,
    LegacyExposureStatus,
    LegacyPrivilegeCandidate,
    LegacyPrivilegeImpact,
    LegacyServiceAssessment,
    LegacyServicesCollector,
    LegacyServicesReport,
    LegacyServiceType,
    OfflineSyntheticLegacyCollector,
    StandardSocketLegacyCollector,
    assess_legacy_services,
)
from cops.discovery.cli import command_legacy_discovery


class TestLegacyModelsAndSerialization(unittest.TestCase):
    def test_legacy_privilege_candidate_post_init_and_serialization(self):
        cand = LegacyPrivilegeCandidate(
            candidate_id="cand-ipmi-01",
            service_type="ipmi",
            category="out_of_band_hardware_management",
            target_host="bmc01.corp.internal",
            port=623,
            vantage="external",
            finding_type="ipmi_cipher_zero_bypass",
            auth_prerequisites=LegacyAuthPrerequisite.CIPHER_ZERO.value,
            privilege_impact=LegacyPrivilegeImpact.HARDWARE_BMC_TAKEOVER.value,
            execution_effect=ExecutionEffect.CODE_EXECUTION.value,
        )
        self.assertTrue(cand.evidence_hash)
        self.assertIn("Cipher 0", cand.remediation_guidance)
        d = cand.to_dict()
        reconstructed = LegacyPrivilegeCandidate.from_dict(d)
        self.assertEqual(reconstructed.candidate_id, cand.candidate_id)
        self.assertEqual(reconstructed.evidence_hash, cand.evidence_hash)
        self.assertEqual(reconstructed.remediation_guidance, cand.remediation_guidance)
        self.assertEqual(reconstructed.privilege_impact, LegacyPrivilegeImpact.HARDWARE_BMC_TAKEOVER.value)
        self.assertEqual(reconstructed.execution_effect, ExecutionEffect.CODE_EXECUTION.value)

    def test_all_10_finding_types_default_remediation(self):
        finding_types = [
            "ndmp_unauthenticated_access",
            "iscsi_unauthenticated_target",
            "ipmi_cipher_zero_bypass",
            "ipmi_rakp_hash_dump",
            "cisco_smart_install_rce",
            "tacacs_unauthenticated_daemon",
            "ike_aggressive_mode_psk",
            "pptp_mschapv2_exposure",
            "socks_open_proxy",
            "squid_open_proxy",
        ]
        for ft in finding_types:
            cand = LegacyPrivilegeCandidate(
                candidate_id=f"cand-{ft}",
                service_type="legacy",
                category="legacy",
                target_host="target",
                port=1234,
                finding_type=ft,
            )
            self.assertTrue(cand.remediation_guidance)
            self.assertFalse(cand.remediation_guidance.startswith("Harden authentication, access control"))

    def test_cleanup_receipt_post_init_and_serialization(self):
        receipt = CleanupReceipt(
            receipt_id="rec-leg-001",
            target_host="bmc01.corp.internal",
            service_type="ipmi",
            artifact_type="canary_legacy_artifact",
            artifact_identifier="cops_canary_test_probe",
            action_taken="verified_removed",
            verified_clean=True,
        )
        self.assertTrue(receipt.receipt_hash)
        d = receipt.to_dict()
        reconstructed = CleanupReceipt.from_dict(d)
        self.assertEqual(reconstructed.receipt_id, receipt.receipt_id)
        self.assertEqual(reconstructed.receipt_hash, receipt.receipt_hash)
        self.assertEqual(reconstructed.action_taken, "verified_removed")
        self.assertTrue(reconstructed.verified_clean)

    def test_legacy_service_assessment_serialization(self):
        cand = LegacyPrivilegeCandidate(
            candidate_id="cand-smi-01",
            service_type="cisco_smart_install",
            category="network_device_appliance_management",
            target_host="switch01.corp.internal",
            port=4786,
            finding_type="cisco_smart_install_rce",
            execution_effect=ExecutionEffect.CODE_EXECUTION.value,
        )
        receipt = CleanupReceipt(
            receipt_id="rec-smi-01",
            target_host="switch01.corp.internal",
            service_type="cisco_smart_install",
            artifact_type="canary_config_probe",
            artifact_identifier="canary_smi_probe",
        )
        ass = LegacyServiceAssessment(
            target_host="switch01.corp.internal",
            resolved_ip="198.51.100.60",
            service_type="cisco_smart_install",
            category="network_device_appliance_management",
            port=4786,
            protocol="tcp",
            vantage="internal",
            exposure_status=LegacyExposureStatus.EXPOSED.value,
            canary_validated=True,
            canary_identifier="canary_smi_probe",
            authentication_required=False,
            auth_prerequisite=LegacyAuthPrerequisite.NONE.value,
            assigned_role="cisco-director",
            can_execute_code=True,
            can_change_state=True,
            bound_to_plan=True,
            proxy_egress_tested=False,
            proxy_egress_restricted=None,
            applicable_versions=["Cisco IOS 15.2"],
            configuration_details={"smi_active": True},
            observed_vulnerabilities=["Cisco Smart Install RCE"],
            uncertainty_notes=[],
            privilege_candidates=[cand],
            cleanup_receipts=[receipt],
        )
        d = ass.to_dict()
        reconstructed = LegacyServiceAssessment.from_dict(d)
        self.assertEqual(reconstructed.target_host, ass.target_host)
        self.assertEqual(reconstructed.service_type, ass.service_type)
        self.assertEqual(reconstructed.exposure_status, ass.exposure_status)
        self.assertTrue(reconstructed.can_execute_code)
        self.assertTrue(reconstructed.can_change_state)
        self.assertEqual(len(reconstructed.privilege_candidates), 1)
        self.assertEqual(len(reconstructed.cleanup_receipts), 1)

    def test_legacy_services_report_serialization_and_disk_roundtrip(self):
        ass = LegacyServiceAssessment(
            target_host="proxy01.corp.internal",
            resolved_ip="198.51.100.70",
            service_type="squid",
            category="proxy_egress_services",
            port=3128,
            protocol="tcp",
            vantage="external",
            exposure_status=LegacyExposureStatus.EXPOSED.value,
            canary_validated=True,
            proxy_egress_tested=True,
            proxy_egress_restricted=False,
        )
        rep = LegacyServicesReport(
            report_id="rep-leg-001",
            target_scope=["proxy01.corp.internal"],
            vantage="external",
            assessments=[ass],
            total_probed=1,
            total_exposed=1,
            candidates_count=0,
            cleanup_receipts_count=0,
        )
        with tempfile.TemporaryDirectory() as td:
            save_path = Path(td) / "report.json"
            rep.save(save_path)
            self.assertTrue(save_path.is_file())

            loaded = LegacyServicesReport.load(save_path)
            self.assertEqual(loaded.report_id, rep.report_id)
            self.assertEqual(len(loaded.assessments), 1)
            self.assertEqual(loaded.assessments[0].service_type, "squid")
            self.assertTrue(loaded.assessments[0].proxy_egress_tested)
            self.assertFalse(loaded.assessments[0].proxy_egress_restricted)

    def test_enum_taxonomy_completeness(self):
        self.assertEqual(len(LegacyServiceType), 9)
        self.assertEqual(len(LegacyCategory), 5)
        self.assertEqual(len(DEFAULT_LEGACY_PORTS), 9)
        for st in LegacyServiceType:
            self.assertIn(st.value, DEFAULT_LEGACY_PORTS)


class TestOfflineSyntheticLegacyCollector(unittest.TestCase):
    def setUp(self):
        self.mock_targets = {
            "storage01.corp.internal": {
                "ndmp": {"auth_required": False, "version": "NDMPv4"},
                "iscsi": {"chap_enforced": False, "targets": ["iqn.2026-10.corp.storage:lun01"]},
            },
            "mgmt01.corp.internal": {
                "ipmi": {"cipher_zero": True, "version": "IPMI 2.0"},
                "cisco_smart_install": {"smi_active": True, "version": "Cisco IOS 15.0"},
                "tacacs": {"auth_required": False, "single_connect": True},
            },
            "vpn01.corp.internal": {
                "ike": {"aggressive_mode": True, "transform": "3DES-SHA1-MODP1024"},
                "pptp": {"mschapv2": True, "firmware": "Poptop 1.4.0"},
            },
            "proxy01.corp.internal": {
                "socks": {"auth_required": False, "egress_restricted": False, "version": "SOCKS5"},
                "squid": {"open_proxy": True, "egress_restricted": False, "version": "Squid 4.13"},
            },
            "hardened.corp.internal": {
                "ndmp": {"protected": True, "auth_required": True},
                "iscsi": {"protected": True, "chap_enforced": True},
                "ipmi": {"protected": True, "cipher_zero_disabled": True, "rakp_auth_enforced": True},
                "cisco_smart_install": {"protected": True, "no_vstack": True},
                "tacacs": {"protected": True, "shared_key_enforced": True, "tls_enabled": True},
                "ike": {"protected": True, "ikev2_only": True},
                "pptp": {"protected": True, "decommissioned": True},
                "socks": {"protected": True, "auth_required": True, "egress_restricted": True},
                "squid": {"protected": True, "acl_enforced": True, "egress_restricted": True},
            },
            "remediated.corp.internal": {
                "ndmp": {"remediated": True, "role": "admin"},
                "socks": {"remediated": True, "role": "proxy_user"},
            },
            "inaccessible.corp.internal": {
                "unreachable": True,
            },
        }

    def test_assess_all_9_protocols_vulnerable(self):
        collector = OfflineSyntheticLegacyCollector(
            targets=self.mock_targets,
            allow_code_execution=True,
            allow_state_change=True,
        )
        report = assess_legacy_services(
            targets=[
                "storage01.corp.internal",
                "mgmt01.corp.internal",
                "vpn01.corp.internal",
                "proxy01.corp.internal",
            ],
            collector=collector,
            vantage="internal",
            canary_id="canary_full_probe",
            allow_code_execution=True,
            allow_state_change=True,
        )
        self.assertEqual(report.total_probed, 36)
        self.assertEqual(report.total_exposed, 9)
        self.assertEqual(report.total_inaccessible, 27)
        self.assertGreaterEqual(report.candidates_count, 9)
        self.assertEqual(report.cleanup_receipts_count, 9)

        # Verify proxy egress testing
        socks_ass = next(a for a in report.assessments if a.service_type == "socks" and a.target_host == "proxy01.corp.internal")
        self.assertTrue(socks_ass.proxy_egress_tested)
        self.assertFalse(socks_ass.proxy_egress_restricted)

        squid_ass = next(a for a in report.assessments if a.service_type == "squid" and a.target_host == "proxy01.corp.internal")
        self.assertTrue(squid_ass.proxy_egress_tested)
        self.assertFalse(squid_ass.proxy_egress_restricted)

        # Verify code execution
        ipmi_ass = next(a for a in report.assessments if a.service_type == "ipmi" and a.target_host == "mgmt01.corp.internal")
        self.assertTrue(ipmi_ass.can_execute_code)

        smi_ass = next(a for a in report.assessments if a.service_type == "cisco_smart_install" and a.target_host == "mgmt01.corp.internal")
        self.assertTrue(smi_ass.can_execute_code)

    def test_collector_helper_methods(self):
        collector = OfflineSyntheticLegacyCollector(
            targets=self.mock_targets,
            allow_code_execution=True,
            allow_state_change=True,
        )
        ndmp_res = collector.assess_ndmp("storage01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(ndmp_res.service_type, "ndmp")
        self.assertEqual(ndmp_res.port, 10000)

        iscsi_res = collector.assess_iscsi("storage01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(iscsi_res.service_type, "iscsi")
        self.assertEqual(iscsi_res.port, 3260)

        ipmi_res = collector.assess_ipmi("mgmt01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(ipmi_res.service_type, "ipmi")
        self.assertEqual(ipmi_res.port, 623)
        self.assertEqual(ipmi_res.protocol, "udp")

        smi_res = collector.assess_cisco_smart_install("mgmt01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(smi_res.service_type, "cisco_smart_install")
        self.assertEqual(smi_res.port, 4786)

        tacacs_res = collector.assess_tacacs("mgmt01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(tacacs_res.service_type, "tacacs")
        self.assertEqual(tacacs_res.port, 49)

        ike_res = collector.assess_ike("vpn01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(ike_res.service_type, "ike")
        self.assertEqual(ike_res.port, 500)
        self.assertEqual(ike_res.protocol, "udp")

        pptp_res = collector.assess_pptp("vpn01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(pptp_res.service_type, "pptp")
        self.assertEqual(pptp_res.port, 1723)

        socks_res = collector.assess_socks("proxy01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(socks_res.service_type, "socks")
        self.assertEqual(socks_res.port, 1080)

        squid_res = collector.assess_squid("proxy01.corp.internal", canary_artifact="canary_01")
        self.assertEqual(squid_res.service_type, "squid")
        self.assertEqual(squid_res.port, 3128)

    def test_code_execution_gated_when_not_authorized(self):
        collector = OfflineSyntheticLegacyCollector(
            targets=self.mock_targets,
            allow_code_execution=False,
            allow_state_change=False,
        )
        report = assess_legacy_services(
            targets=["mgmt01.corp.internal"],
            service_types=["ipmi", "cisco_smart_install"],
            collector=collector,
            allow_code_execution=False,
            allow_state_change=False,
        )
        for ass in report.assessments:
            self.assertFalse(ass.can_execute_code)
            self.assertTrue(any("Code execution verification skipped" in u for u in ass.uncertainty_notes))

    def test_protected_services(self):
        collector = OfflineSyntheticLegacyCollector(targets=self.mock_targets)
        report = assess_legacy_services(
            targets=["hardened.corp.internal"],
            collector=collector,
            canary_id="canary_hardened",
        )
        self.assertEqual(report.total_probed, 9)
        self.assertEqual(report.total_protected, 9)
        self.assertEqual(report.candidates_count, 0)
        self.assertEqual(report.cleanup_receipts_count, 9)

        socks_ass = next(a for a in report.assessments if a.service_type == "socks")
        self.assertTrue(socks_ass.proxy_egress_tested)
        self.assertTrue(socks_ass.proxy_egress_restricted)

        squid_ass = next(a for a in report.assessments if a.service_type == "squid")
        self.assertTrue(squid_ass.proxy_egress_tested)
        self.assertTrue(squid_ass.proxy_egress_restricted)

    def test_remediated_services(self):
        collector = OfflineSyntheticLegacyCollector(targets=self.mock_targets)
        report = assess_legacy_services(
            targets=["remediated.corp.internal"],
            service_types=["ndmp", "socks"],
            collector=collector,
            canary_id="canary_remediated",
        )
        self.assertEqual(report.total_probed, 2)
        self.assertEqual(report.assessments[0].exposure_status, LegacyExposureStatus.REMEDIATED.value)
        self.assertEqual(report.assessments[1].exposure_status, LegacyExposureStatus.REMEDIATED.value)

    def test_truth_boundary_inaccessible_never_protected(self):
        collector = OfflineSyntheticLegacyCollector(targets=self.mock_targets)
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


class TestStandardSocketLegacyCollector(unittest.TestCase):
    @patch("socket.gethostbyname")
    @patch("socket.create_connection")
    def test_tcp_socket_connect_success(self, mock_connect, mock_resolve):
        mock_resolve.return_value = "198.51.100.99"
        mock_connect.return_value.__enter__.return_value = MagicMock()

        collector = StandardSocketLegacyCollector()
        ass = collector.probe_service(
            target_host="storage.corp.internal",
            resolved_ip="198.51.100.99",
            service_type="ndmp",
            port=10000,
            protocol="tcp",
            canary_artifact="canary_01",
        )
        self.assertEqual(ass.exposure_status, LegacyExposureStatus.EXPOSED.value)
        self.assertTrue(ass.configuration_details.get("socket_connected"))
        self.assertTrue(ass.canary_validated)
        self.assertEqual(ass.auth_prerequisite, LegacyAuthPrerequisite.UNKNOWN.value)

    @patch("socket.gethostbyname")
    @patch("socket.socket")
    def test_udp_socket_probe_success(self, mock_socket_cls, mock_resolve):
        mock_resolve.return_value = "198.51.100.99"
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        collector = StandardSocketLegacyCollector()
        ass = collector.probe_service(
            target_host="bmc.corp.internal",
            resolved_ip="198.51.100.99",
            service_type="ipmi",
            port=623,
            protocol="udp",
            canary_artifact="canary_01",
        )
        self.assertEqual(ass.exposure_status, LegacyExposureStatus.EXPOSED.value)
        self.assertTrue(ass.configuration_details.get("udp_datagram_sent"))
        mock_sock.sendto.assert_called_once_with(b"\x00", ("198.51.100.99", 623))

    @patch("socket.gethostbyname")
    @patch("socket.create_connection")
    def test_tcp_socket_timeout_inaccessible(self, mock_connect, mock_resolve):
        mock_resolve.return_value = "198.51.100.99"
        mock_connect.side_effect = socket.timeout("timed out")

        collector = StandardSocketLegacyCollector()
        ass = collector.probe_service(
            target_host="filtered.corp.internal",
            resolved_ip="198.51.100.99",
            service_type="ndmp",
            port=10000,
            protocol="tcp",
        )
        self.assertEqual(ass.exposure_status, LegacyExposureStatus.INACCESSIBLE.value)
        self.assertEqual(ass.auth_prerequisite, LegacyAuthPrerequisite.UNKNOWN.value)
        self.assertTrue(any("cannot be reported as secure" in u for u in ass.uncertainty_notes))


class TestLegacyDiscoveryCLI(unittest.TestCase):
    def setUp(self):
        self.mock_data = {
            "leg01.corp.internal": {
                "ndmp": {"auth_required": False, "version": "NDMPv4"},
                "socks": {"auth_required": False, "egress_restricted": False, "version": "SOCKS5"},
            }
        }

    def test_cli_assess_candidates_cleanup_inspect(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            offline_file = td_path / "targets.json"
            offline_file.write_text(json.dumps(self.mock_data), encoding="utf-8")

            report_file = td_path / "legacy_report.json"
            cand_file = td_path / "legacy_candidates.json"
            clean_file = td_path / "legacy_cleanup.json"

            # 1. Assess
            args_assess = argparse.Namespace(
                legacy_command="assess",
                targets="leg01.corp.internal",
                services="ndmp,socks",
                vantage="internal",
                scope_ref="authorized-scope",
                canary_id="canary_cli_test",
                allow_code_execution=False,
                allow_state_change=True,
                mode="synthetic",
                offline_targets=str(offline_file),
                output=str(report_file),
            )
            ret = command_legacy_discovery(args_assess)
            self.assertEqual(ret, 0)
            self.assertTrue(report_file.is_file())

            # 2. Candidates
            args_cand = argparse.Namespace(
                legacy_command="candidates",
                report=str(report_file),
                output=str(cand_file),
            )
            ret = command_legacy_discovery(args_cand)
            self.assertEqual(ret, 0)
            self.assertTrue(cand_file.is_file())
            candidates = json.loads(cand_file.read_text(encoding="utf-8"))
            self.assertEqual(len(candidates), 2)

            # 3. Cleanup
            args_clean = argparse.Namespace(
                legacy_command="cleanup",
                report=str(report_file),
                output=str(clean_file),
            )
            ret = command_legacy_discovery(args_clean)
            self.assertEqual(ret, 0)
            self.assertTrue(clean_file.is_file())
            receipts = json.loads(clean_file.read_text(encoding="utf-8"))
            self.assertEqual(len(receipts), 2)
            self.assertTrue(all(r["action_taken"] == "verified_removed" for r in receipts))

            # 4. Inspect JSON
            args_insp_json = argparse.Namespace(
                legacy_command="inspect",
                report=str(report_file),
                json=True,
            )
            captured = io.StringIO()
            with patch("sys.stdout", captured):
                ret = command_legacy_discovery(args_insp_json)
            self.assertEqual(ret, 0)
            out_obj = json.loads(captured.getvalue())
            self.assertEqual(out_obj["total_probed"], 2)

            # 5. Inspect Text
            args_insp_text = argparse.Namespace(
                legacy_command="inspect",
                report=str(report_file),
                json=False,
            )
            captured_text = io.StringIO()
            with patch("sys.stdout", captured_text):
                ret = command_legacy_discovery(args_insp_text)
            self.assertEqual(ret, 0)
            self.assertIn("Legacy Enterprise, Management & Proxy Services Report", captured_text.getvalue())
            self.assertIn("NDMP", captured_text.getvalue())
            self.assertIn("SOCKS", captured_text.getvalue())


if __name__ == "__main__":
    unittest.main()
