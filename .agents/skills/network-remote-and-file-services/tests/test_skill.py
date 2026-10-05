"""Tests for network-remote-and-file-services contributor skill."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    CleanupReceipt,
    HostPrivilegeCandidate,
    LateralMovementImpact,
    OfflineSyntheticRemoteCollector,
    RemoteAuthPrerequisite,
    RemoteExposureStatus,
    RemoteServiceAssessment,
    RemoteServiceCategory,
    RemoteServicesReport,
    RemoteServiceType,
    assess_remote_services,
)
from cops.discovery.cli import command_remote_discovery
import argparse


class TestNetworkRemoteAndFileServicesSkill(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "vulnerable-host.corp.internal": {
                "ssh": {
                    "password_auth": True,
                    "publickey_auth": False,
                    "version": "OpenSSH 7.4",
                },
                "telnet": {
                    "banner": "Cisco IOS Experimental Telnet",
                    "auth_required": True,
                },
                "rdp": {
                    "nla_enabled": False,
                    "security_layer": "RDP",
                },
                "vnc": {
                    "auth_required": False,
                    "rfb_version": "003.008",
                },
                "winrm": {
                    "https_enforced": False,
                    "basic_auth": True,
                },
                "x11": {
                    "auth_required": False,
                    "display": ":0",
                },
                "smb": {
                    "smbv1_enabled": True,
                    "smb_signing_required": False,
                    "shares": ["SYSVOL", "NETLOGON", "PUBLIC_SHARE"],
                    "anonymous_access": True,
                },
                "nfs": {
                    "no_root_squash": True,
                    "exports": ["/opt/backup (world)"],
                },
                "ftp": {
                    "anonymous_enabled": True,
                    "anonymous_login": True,
                    "banner": "ProFTPD 1.3.5",
                },
                "rsync": {
                    "auth_users_required": False,
                    "modules": ["data_dump", "mirror"],
                },
                "ipp": {
                    "auth_required": False,
                    "printers": ["main_office_printer"],
                },
            },
            "hardened-host.corp.internal": {
                "ssh": {
                    "password_auth": False,
                    "publickey_auth": True,
                    "version": "OpenSSH 9.2",
                    "protected": True,
                },
                "rdp": {
                    "nla_enabled": True,
                    "security_layer": "SSL",
                    "protected": True,
                },
                "smb": {
                    "smbv1_enabled": False,
                    "smb_signing_required": True,
                    "anonymous_access": False,
                    "protected": True,
                },
                "vnc": {
                    "auth_required": True,
                    "protected": True,
                },
                "winrm": {
                    "https_enforced": True,
                    "basic_auth": False,
                    "protected": True,
                },
                "nfs": {
                    "no_root_squash": False,
                    "world_accessible": False,
                    "protected": True,
                },
            },
            "remediated-host.corp.internal": {
                "smb": {
                    "remediated": True,
                    "auth_prerequisite": "kerberos",
                    "version": "SMBv3.1.1 (SMBv1 disabled)",
                }
            },
            "filtered-host.corp.internal": {
                "ssh": {"state": "filtered"},
                "smb": {"state": "closed"},
                "rdp": {"inaccessible": True},
            },
        }
        self.collector = OfflineSyntheticRemoteCollector(targets=self.mock_services)

    def test_positive_exposure_and_host_privilege_candidates(self):
        """Test assessment identifies vulnerabilities and generates HostPrivilegeCandidates."""
        report = assess_remote_services(
            targets=["vulnerable-host.corp.internal"],
            collector=self.collector,
            vantage="internal",
            canary_artifact="canary_share/audit.tmp",
        )

        self.assertIsInstance(report, RemoteServicesReport)
        self.assertGreater(len(report.services_assessed), 0)
        self.assertGreater(len(report.host_privilege_candidates), 0)

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

        # Check lateral movement impact ratings
        nfs_cand = next(c for c in report.host_privilege_candidates if c.finding_type == "nfs_no_root_squash")
        self.assertEqual(nfs_cand.lateral_movement_impact, LateralMovementImpact.PRIVILEGE_ESCALATION.value)

        smb_signing_cand = next(c for c in report.host_privilege_candidates if c.finding_type == "smb_signing_disabled")
        self.assertEqual(smb_signing_cand.lateral_movement_impact, LateralMovementImpact.CREDENTIAL_HARVESTING.value)

        vnc_cand = next(c for c in report.host_privilege_candidates if c.finding_type == "vnc_no_auth")
        self.assertEqual(vnc_cand.lateral_movement_impact, LateralMovementImpact.COMMAND_EXECUTION.value)

    def test_canary_validation_and_cleanup_receipts(self):
        """Test canary file access generates verifiable CleanupReceipts."""
        report = assess_remote_services(
            targets=["vulnerable-host.corp.internal"],
            service_types=["smb"],
            collector=self.collector,
            vantage="internal",
            canary_artifact="canary_share/audit.tmp",
        )

        self.assertEqual(len(report.cleanup_receipts), 1)
        receipt = report.cleanup_receipts[0]
        self.assertEqual(receipt.artifact_identifier, "canary_share/audit.tmp")
        self.assertEqual(receipt.action_taken, "verified_removed")
        self.assertTrue(receipt.verified_clean)
        self.assertTrue(receipt.receipt_hash)

    def test_protected_services(self):
        """Test hardened services are reported as protected with proper auth prerequisites."""
        report = assess_remote_services(
            targets=["hardened-host.corp.internal"],
            service_types=["ssh", "rdp", "smb", "vnc", "winrm", "nfs"],
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

    def test_remediated_services(self):
        """Test remediated status and version records."""
        report = assess_remote_services(
            targets=["remediated-host.corp.internal"],
            service_types=["smb"],
            collector=self.collector,
            vantage="internal",
        )

        self.assertEqual(len(report.services_assessed), 1)
        s = report.services_assessed[0]
        self.assertEqual(s.exposure_status, RemoteExposureStatus.REMEDIATED.value)
        self.assertEqual(s.auth_prerequisite, RemoteAuthPrerequisite.KERBEROS.value)

    def test_strict_inaccessible_not_secure(self):
        """Crucial Truth Boundary: Filtered or unreachable services are NEVER reported as secure/protected."""
        report = assess_remote_services(
            targets=["filtered-host.corp.internal"],
            service_types=["ssh", "smb", "rdp"],
            collector=self.collector,
            vantage="external",
        )

        for s in report.services_assessed:
            self.assertEqual(s.exposure_status, RemoteExposureStatus.INACCESSIBLE.value)
            self.assertNotEqual(s.exposure_status, RemoteExposureStatus.PROTECTED.value)
            self.assertEqual(s.auth_prerequisite, RemoteAuthPrerequisite.UNKNOWN.value)
            self.assertIn("cannot be reported as secure or hardened", s.uncertainty_notes[0])

    def test_cli_integration(self):
        """Test remote discovery CLI subcommands."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            targets_file = tmp_path / "mock_targets.json"
            targets_file.write_text(json.dumps(self.mock_services), encoding="utf-8")

            report_file = tmp_path / "report.json"
            candidates_file = tmp_path / "candidates.json"
            cleanup_file = tmp_path / "cleanup.json"

            # 1. assess
            args_assess = argparse.Namespace(
                remote_command="assess",
                targets="vulnerable-host.corp.internal",
                services="smb,rdp,ssh",
                vantage="internal",
                scope_ref="scope-e04-04",
                canary_id="canary_share/audit.tmp",
                mode="synthetic",
                offline_targets=str(targets_file),
                output=str(report_file),
            )
            rc = command_remote_discovery(args_assess)
            self.assertEqual(rc, 0)
            self.assertTrue(report_file.exists())

            # 2. candidates
            args_cand = argparse.Namespace(
                remote_command="candidates",
                report=str(report_file),
                output=str(candidates_file),
            )
            rc = command_remote_discovery(args_cand)
            self.assertEqual(rc, 0)
            self.assertTrue(candidates_file.exists())

            # 3. cleanup
            args_clean = argparse.Namespace(
                remote_command="cleanup",
                report=str(report_file),
                output=str(cleanup_file),
            )
            rc = command_remote_discovery(args_clean)
            self.assertEqual(rc, 0)
            self.assertTrue(cleanup_file.exists())

            # 4. inspect
            args_insp = argparse.Namespace(
                remote_command="inspect",
                report=str(report_file),
                json=False,
            )
            rc = command_remote_discovery(args_insp)
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
