"""Unit, contract, and CLI tests for remote administration, file sharing, and printing services assessment."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    CleanupReceipt,
    DEFAULT_REMOTE_PORTS,
    HostPrivilegeCandidate,
    LateralMovementImpact,
    OfflineSyntheticRemoteCollector,
    RemoteAuthPrerequisite,
    RemoteExposureStatus,
    RemoteServiceAssessment,
    RemoteServiceCategory,
    RemoteServicesCollector,
    RemoteServicesReport,
    RemoteServiceType,
    StandardSocketRemoteCollector,
    assess_remote_services,
)
from cops.discovery.cli import command_remote_discovery


class TestRemoteModelsAndSerialization(unittest.TestCase):
    def test_host_privilege_candidate_post_init_and_serialization(self):
        cand = HostPrivilegeCandidate(
            candidate_id="cand-smb-01",
            service_type="smb",
            category="file_sharing",
            target_host="fileserver.corp.internal",
            port=445,
            vantage="internal",
            finding_type="smb_v1_enabled",
            auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
            lateral_movement_impact=LateralMovementImpact.COMMAND_EXECUTION.value,
        )
        self.assertTrue(cand.evidence_hash)
        self.assertIn("SMBv1", cand.remediation_guidance)
        d = cand.to_dict()
        reconstructed = HostPrivilegeCandidate.from_dict(d)
        self.assertEqual(reconstructed.candidate_id, cand.candidate_id)
        self.assertEqual(reconstructed.evidence_hash, cand.evidence_hash)
        self.assertEqual(reconstructed.remediation_guidance, cand.remediation_guidance)
        self.assertEqual(reconstructed.lateral_movement_impact, LateralMovementImpact.COMMAND_EXECUTION.value)

    def test_cleanup_receipt_post_init_and_serialization(self):
        receipt = CleanupReceipt(
            receipt_id="rec-001",
            target_host="print01.corp.internal",
            service_type="ipp",
            artifact_type="canary_print_job",
            artifact_identifier="canary_print_job_probe",
            action_taken="verified_removed",
            verified_clean=True,
        )
        self.assertTrue(receipt.receipt_hash)
        d = receipt.to_dict()
        reconstructed = CleanupReceipt.from_dict(d)
        self.assertEqual(reconstructed.receipt_id, receipt.receipt_id)
        self.assertEqual(reconstructed.receipt_hash, receipt.receipt_hash)
        self.assertTrue(reconstructed.verified_clean)

    def test_remote_service_assessment_serialization_roundtrip(self):
        cand = HostPrivilegeCandidate(
            candidate_id="cand-rdp-01",
            service_type="rdp",
            category="remote_admin",
            target_host="win-srv01.corp.internal",
            port=3389,
            vantage="external",
            finding_type="rdp_nla_disabled",
            auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
            lateral_movement_impact=LateralMovementImpact.COMMAND_EXECUTION.value,
        )
        receipt = CleanupReceipt(
            receipt_id="rec-002",
            target_host="win-srv01.corp.internal",
            service_type="rdp",
            artifact_type="canary_session",
            artifact_identifier="canary_rdp_check",
            action_taken="verified_removed",
            verified_clean=True,
        )
        assessment = RemoteServiceAssessment(
            target_host="win-srv01.corp.internal",
            resolved_ip="198.51.100.55",
            service_type=RemoteServiceType.RDP.value,
            category=RemoteServiceCategory.REMOTE_ADMIN.value,
            port=3389,
            protocol="tcp",
            vantage="external",
            exposure_status=RemoteExposureStatus.EXPOSED.value,
            canary_validated=True,
            canary_identifier="canary_rdp_check",
            authentication_required=False,
            auth_prerequisite=RemoteAuthPrerequisite.NONE.value,
            host_privilege_candidates=[cand],
            cleanup_receipts=[receipt],
        )
        d = assessment.to_dict()
        reconstructed = RemoteServiceAssessment.from_dict(d)
        self.assertEqual(reconstructed.target_host, assessment.target_host)
        self.assertEqual(reconstructed.port, assessment.port)
        self.assertEqual(len(reconstructed.host_privilege_candidates), 1)
        self.assertEqual(len(reconstructed.cleanup_receipts), 1)
        self.assertEqual(reconstructed.host_privilege_candidates[0].candidate_id, cand.candidate_id)

    def test_remote_services_report_serialization_and_save(self):
        report = RemoteServicesReport(
            report_id="remote-rep-01",
            scope_reference="scope-test",
            vantage="internal",
            summary={"total_services": 1, "exposed": 1},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.json"
            report.save(out_file)
            self.assertTrue(out_file.is_file())
            loaded = RemoteServicesReport.load(out_file)
            self.assertEqual(loaded.report_id, report.report_id)
            self.assertEqual(loaded.summary["total_services"], 1)


class TestOfflineSyntheticRemoteCollector(unittest.TestCase):
    def setUp(self):
        self.targets = {
            "vulnerable.lab.internal": {
                "ssh": {"password_auth": True, "publickey_auth": False, "version": "OpenSSH 6.6.1"},
                "telnet": {"banner": "Login:", "auth_required": True},
                "rdp": {"nla_enabled": False, "security_layer": "RDP"},
                "vnc": {"auth_required": False, "rfb_version": "003.008"},
                "winrm": {"https_enforced": False, "port": 5985},
                "x11": {"auth_required": False, "display": ":0"},
                "smb": {
                    "smbv1_enabled": True,
                    "smb_signing_required": False,
                    "shares": ["backup", "public"],
                    "anonymous_access": True,
                },
                "nfs": {"no_root_squash": True, "exports": ["/data (rw)"]},
                "ftp": {"anonymous_enabled": True, "banner": "vsftpd 2.3.4"},
                "rsync": {"auth_users_required": False, "modules": ["shared_src"]},
                "afp": {"guest_access": True, "volumes": ["TimeMachine"]},
                "lpd": {"auth_required": False, "printers": ["lp0"]},
                "ipp": {"auth_required": False, "printers": ["printer_color"]},
                "raw_print": {"auth_required": False},
            },
            "hardened.lab.internal": {
                "ssh": {"password_auth": False, "publickey_auth": True, "version": "OpenSSH 9.5", "protected": True},
                "rdp": {"nla_enabled": True, "protected": True},
                "smb": {
                    "smbv1_enabled": False,
                    "smb_signing_required": True,
                    "anonymous_access": False,
                    "protected": True,
                },
                "vnc": {"auth_required": True, "protected": True},
                "winrm": {"https_enforced": True, "protected": True},
                "nfs": {"no_root_squash": False, "world_accessible": False, "protected": True},
                "ftp": {"anonymous_enabled": False, "protected": True},
                "rsync": {"auth_users_required": True, "protected": True},
                "afp": {"guest_access": False, "protected": True},
                "ipp": {"auth_required": True, "protected": True},
            },
            "remediated.lab.internal": {
                "smb": {"remediated": True, "auth_prerequisite": "kerberos", "version": "SMBv3.1.1 (SMBv1 disabled)"}
            },
            "filtered.lab.internal": {
                "ssh": {"state": "filtered"},
                "rdp": {"state": "closed"},
                "smb": {"inaccessible": True},
            },
        }
        self.collector = OfflineSyntheticRemoteCollector(targets=self.targets)

    def test_assess_all_15_protocols_on_vulnerable_host(self):
        report = assess_remote_services(
            targets=["vulnerable.lab.internal"],
            collector=self.collector,
            vantage="internal",
            canary_artifact="canary_share/audit.tmp",
        )
        self.assertEqual(len(report.services_assessed), len(DEFAULT_REMOTE_PORTS))
        self.assertGreater(len(report.host_privilege_candidates), 10)
        self.assertGreater(len(report.cleanup_receipts), 0)

        finding_types = {c.finding_type for c in report.host_privilege_candidates}
        self.assertIn("smb_v1_enabled", finding_types)
        self.assertIn("smb_signing_disabled", finding_types)
        self.assertIn("smb_unauthenticated_share", finding_types)
        self.assertIn("telnet_plaintext_exposure", finding_types)
        self.assertIn("rdp_nla_disabled", finding_types)
        self.assertIn("vnc_no_auth", finding_types)
        self.assertIn("winrm_http_unencrypted", finding_types)
        self.assertIn("x11_open_display", finding_types)
        self.assertIn("nfs_no_root_squash", finding_types)
        self.assertIn("ftp_anonymous_login", finding_types)
        self.assertIn("rsync_open_module", finding_types)
        self.assertIn("unauthenticated_printer_queue", finding_types)

    def test_strict_inaccessible_not_secure_grounding(self):
        """Verify that filtered, closed, or timeout services are strictly inaccessible and NEVER protected."""
        report = assess_remote_services(
            targets=["filtered.lab.internal"],
            service_types=["ssh", "rdp", "smb"],
            collector=self.collector,
            vantage="external",
        )
        for s in report.services_assessed:
            self.assertEqual(s.exposure_status, RemoteExposureStatus.INACCESSIBLE.value)
            self.assertNotEqual(s.exposure_status, RemoteExposureStatus.PROTECTED.value)
            self.assertEqual(s.auth_prerequisite, RemoteAuthPrerequisite.UNKNOWN.value)
            self.assertTrue(s.uncertainty_notes)
            self.assertIn("cannot be reported as secure or hardened", s.uncertainty_notes[0])

    def test_canary_validation_and_cleanup_receipt_generation(self):
        report = assess_remote_services(
            targets=["vulnerable.lab.internal"],
            service_types=["smb", "ipp"],
            collector=self.collector,
            vantage="internal",
            canary_artifact="canary_probe_file.tmp",
        )
        self.assertEqual(len(report.cleanup_receipts), 2)
        for r in report.cleanup_receipts:
            self.assertEqual(r.action_taken, "verified_removed")
            self.assertTrue(r.verified_clean)
            self.assertTrue(r.receipt_hash)

    def test_protected_services_classification(self):
        report = assess_remote_services(
            targets=["hardened.lab.internal"],
            service_types=["ssh", "rdp", "smb", "vnc", "winrm", "nfs", "ftp", "rsync", "afp", "ipp"],
            collector=self.collector,
            vantage="internal",
        )
        for s in report.services_assessed:
            self.assertEqual(s.exposure_status, RemoteExposureStatus.PROTECTED.value)
            self.assertTrue(s.authentication_required)

        ssh_svc = next(s for s in report.services_assessed if s.service_type == "ssh")
        self.assertEqual(ssh_svc.auth_prerequisite, RemoteAuthPrerequisite.PUBLIC_KEY.value)

        rdp_svc = next(s for s in report.services_assessed if s.service_type == "rdp")
        self.assertEqual(rdp_svc.auth_prerequisite, RemoteAuthPrerequisite.NLA_REQUIRED.value)

        smb_svc = next(s for s in report.services_assessed if s.service_type == "smb")
        self.assertEqual(smb_svc.auth_prerequisite, RemoteAuthPrerequisite.KERBEROS.value)

    def test_remediated_service_classification(self):
        report = assess_remote_services(
            targets=["remediated.lab.internal"],
            service_types=["smb"],
            collector=self.collector,
            vantage="internal",
        )
        self.assertEqual(len(report.services_assessed), 1)
        s = report.services_assessed[0]
        self.assertEqual(s.exposure_status, RemoteExposureStatus.REMEDIATED.value)
        self.assertEqual(s.auth_prerequisite, RemoteAuthPrerequisite.KERBEROS.value)


class TestStandardSocketRemoteCollector(unittest.TestCase):
    def test_socket_collector_target_resolution(self):
        collector = StandardSocketRemoteCollector()
        resolved = collector.resolve_target("127.0.0.1")
        self.assertEqual(resolved, "127.0.0.1")

    def test_socket_collector_inaccessible_port(self):
        collector = StandardSocketRemoteCollector()
        assessment = collector.probe_service(
            target_host="127.0.0.1",
            resolved_ip="127.0.0.1",
            service_type="ssh",
            port=65534,
            vantage="external",
            timeout=0.1,
        )
        self.assertEqual(assessment.exposure_status, RemoteExposureStatus.INACCESSIBLE.value)
        self.assertEqual(assessment.auth_prerequisite, RemoteAuthPrerequisite.UNKNOWN.value)
        self.assertIn("cannot be reported as secure", assessment.uncertainty_notes[0])


class TestRemoteDiscoveryCLI(unittest.TestCase):
    def setUp(self):
        self.targets = {
            "vulnerable.lab.internal": {
                "smb": {
                    "smbv1_enabled": True,
                    "smb_signing_required": False,
                    "shares": ["SYSVOL"],
                    "anonymous_access": True,
                },
                "rdp": {"nla_enabled": False},
            },
            "unreachable.lab.internal": {
                "smb": {"state": "closed"},
            },
        }

    def test_cli_assess_candidates_cleanup_inspect(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            targets_file = tmp_path / "targets.json"
            targets_file.write_text(json.dumps(self.targets), encoding="utf-8")

            report_file = tmp_path / "report.json"
            candidates_file = tmp_path / "candidates.json"
            cleanup_file = tmp_path / "cleanup.json"

            # 1. Assess
            args_assess = argparse.Namespace(
                remote_command="assess",
                targets=str(targets_file),
                services="smb,rdp",
                vantage="internal",
                scope_ref="roe-lab-01",
                canary_id="canary_share/audit.tmp",
                mode="synthetic",
                offline_targets=str(targets_file),
                output=str(report_file),
            )
            rc = command_remote_discovery(args_assess)
            self.assertEqual(rc, 0)
            self.assertTrue(report_file.is_file())

            # 2. Candidates
            args_cand = argparse.Namespace(
                remote_command="candidates",
                report=str(report_file),
                output=str(candidates_file),
            )
            rc = command_remote_discovery(args_cand)
            self.assertEqual(rc, 0)
            self.assertTrue(candidates_file.is_file())
            cand_data = json.loads(candidates_file.read_text(encoding="utf-8"))
            self.assertGreater(len(cand_data), 0)

            # 3. Cleanup
            args_clean = argparse.Namespace(
                remote_command="cleanup",
                report=str(report_file),
                output=str(cleanup_file),
            )
            rc = command_remote_discovery(args_clean)
            self.assertEqual(rc, 0)
            self.assertTrue(cleanup_file.is_file())
            clean_data = json.loads(cleanup_file.read_text(encoding="utf-8"))
            self.assertGreater(len(clean_data), 0)

            # 4. Inspect (json=True)
            args_insp_json = argparse.Namespace(
                remote_command="inspect",
                report=str(report_file),
                json=True,
            )
            buf = io.StringIO()
            sys.stdout = buf
            try:
                rc = command_remote_discovery(args_insp_json)
                self.assertEqual(rc, 0)
                out = buf.getvalue()
                self.assertIn("remote-", out)
            finally:
                sys.stdout = sys.__stdout__

            # 5. Inspect (text format with Truth-in-Advertising notice)
            args_insp_text = argparse.Namespace(
                remote_command="inspect",
                report=str(report_file),
                json=False,
            )
            buf = io.StringIO()
            sys.stdout = buf
            try:
                rc = command_remote_discovery(args_insp_text)
                self.assertEqual(rc, 0)
                out = buf.getvalue()
                self.assertIn("Truth-in-Advertising Notice: Inaccessible services are NOT reported as secure or hardened", out)
            finally:
                sys.stdout = sys.__stdout__


if __name__ == "__main__":
    unittest.main()
