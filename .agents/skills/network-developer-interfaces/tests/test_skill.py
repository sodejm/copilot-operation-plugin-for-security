"""Tests for network-developer-interfaces contributor skill."""

from __future__ import annotations

import argparse
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
    DeveloperAuthPrerequisite,
    DeveloperCategory,
    DeveloperExposureStatus,
    DeveloperPrivilegeCandidate,
    DeveloperPrivilegeImpact,
    DeveloperServiceAssessment,
    DeveloperServicesReport,
    DeveloperServiceType,
    ExecutionEffect,
    OfflineSyntheticDeveloperCollector,
    assess_developer_services,
)
from cops.discovery.cli import command_developer_discovery


class TestNetworkDeveloperInterfacesSkill(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "vulnerable-dev.corp.internal": {
                "docker": {
                    "socket_exposed": True,
                    "tls_verify": False,
                    "auth_required": False,
                    "version": "Docker 20.10.12",
                },
                "docker_registry": {
                    "catalog_accessible": True,
                    "auth_required": False,
                    "tls_enforced": False,
                    "version": "Docker Registry 2.8.1",
                },
                "rmi": {
                    "unauthenticated_registry": True,
                    "codebase_only": False,
                    "auth_required": False,
                    "version": "Java RMI 11.0.15",
                },
                "jdwp": {
                    "debug_agent_exposed": True,
                    "auth_required": False,
                    "version": "JDWP 1.6.0",
                },
                "erlang_epmd": {
                    "names_accessible": True,
                    "weak_cookie": True,
                    "version": "Erlang EPMD 5.9",
                },
                "adb": {
                    "wireless_debugging": True,
                    "rsa_key_required": False,
                    "version": "Android ADB 1.0.41",
                },
                "distcc": {
                    "allow_cidr_missing": True,
                    "auth_required": False,
                    "version": "distcc 3.3.3",
                },
                "svn": {
                    "anon_access": True,
                    "auth_required": False,
                    "version": "svnserve 1.14.1",
                },
                "ajp": {
                    "secret_required": False,
                    "ghostcat_vulnerable": True,
                    "version": "Apache Tomcat 9.0.30",
                },
                "fastcgi": {
                    "exposed_external": True,
                    "auth_required": False,
                    "version": "PHP-FPM 7.4.28",
                },
            },
            "hardened-dev.corp.internal": {
                "docker": {
                    "protected": True,
                    "tls_verify": True,
                    "auth_required": True,
                    "auth_prerequisite": DeveloperAuthPrerequisite.CLIENT_CERT.value,
                    "version": "Docker 24.0.5",
                },
                "docker_registry": {
                    "protected": True,
                    "auth_required": True,
                    "tls_enforced": True,
                    "auth_prerequisite": DeveloperAuthPrerequisite.TOKEN_OR_API_KEY.value,
                    "version": "Docker Registry 2.8.2",
                },
                "jdwp": {
                    "protected": True,
                    "debug_agent_exposed": False,
                    "auth_required": True,
                    "version": "JDWP Disabled",
                },
                "ajp": {
                    "protected": True,
                    "secret_required": True,
                    "ghostcat_vulnerable": False,
                    "auth_prerequisite": DeveloperAuthPrerequisite.USER_PASSWORD.value,
                    "version": "Apache Tomcat 9.0.31",
                },
            },
            "remediated-dev.corp.internal": {
                "fastcgi": {
                    "remediated": True,
                    "auth_prerequisite": DeveloperAuthPrerequisite.NONE.value,
                    "role": "localhost_only",
                    "version": "PHP-FPM 8.2",
                }
            },
            "firewalled-host.corp.internal": {
                "docker": {"state": "filtered"},
                "jdwp": {"state": "timeout"},
            },
        }
        self.collector = OfflineSyntheticDeveloperCollector(
            targets=self.mock_services,
            allow_code_execution=True,
            allow_state_change=True,
        )

    def test_assess_docker_api_vulnerabilities(self):
        result = self.collector.assess_docker("vulnerable-dev.corp.internal", canary_artifact="canary_docker_container")
        self.assertEqual(result.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(result.canary_validated)
        self.assertEqual(result.canary_identifier, "canary_docker_container")
        self.assertTrue(result.can_execute_code)
        self.assertGreaterEqual(len(result.privilege_candidates), 1)
        finding_types = [c.finding_type for c in result.privilege_candidates]
        self.assertIn("docker_socket_rce", finding_types)
        self.assertEqual(result.privilege_candidates[0].execution_effect, ExecutionEffect.CODE_EXECUTION.value)

    def test_assess_docker_registry_vulnerabilities(self):
        result = self.collector.assess_docker_registry("vulnerable-dev.corp.internal", canary_artifact="canary_repo")
        self.assertEqual(result.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(result.canary_validated)
        finding_types = [c.finding_type for c in result.privilege_candidates]
        self.assertIn("docker_registry_leak", finding_types)

    def test_assess_rmi_and_jdwp_vulnerabilities(self):
        rmi_res = self.collector.assess_rmi("vulnerable-dev.corp.internal")
        self.assertEqual(rmi_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "rmi_code_execution" for c in rmi_res.privilege_candidates))

        jdwp_res = self.collector.assess_jdwp("vulnerable-dev.corp.internal", canary_artifact="canary_jdwp_bp")
        self.assertEqual(jdwp_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(jdwp_res.can_execute_code)
        self.assertTrue(any(c.finding_type == "jdwp_code_execution" for c in jdwp_res.privilege_candidates))

    def test_assess_erlang_epmd_and_adb_vulnerabilities(self):
        epmd_res = self.collector.assess_erlang_epmd("vulnerable-dev.corp.internal")
        self.assertEqual(epmd_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "erlang_epmd_rce" for c in epmd_res.privilege_candidates))

        adb_res = self.collector.assess_adb("vulnerable-dev.corp.internal")
        self.assertEqual(adb_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(adb_res.can_execute_code)
        self.assertTrue(any(c.finding_type == "adb_shell_rce" for c in adb_res.privilege_candidates))

    def test_assess_distcc_and_svn_vulnerabilities(self):
        distcc_res = self.collector.assess_distcc("vulnerable-dev.corp.internal")
        self.assertEqual(distcc_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(distcc_res.can_execute_code)
        self.assertTrue(any(c.finding_type == "distcc_rce" for c in distcc_res.privilege_candidates))

        svn_res = self.collector.assess_svn("vulnerable-dev.corp.internal", canary_artifact="canary_svn_branch")
        self.assertEqual(svn_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "svn_anonymous_checkout" for c in svn_res.privilege_candidates))

    def test_assess_ajp_and_fastcgi_vulnerabilities(self):
        ajp_res = self.collector.assess_ajp("vulnerable-dev.corp.internal")
        self.assertEqual(ajp_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "ajp_ghostcat_rce" for c in ajp_res.privilege_candidates))

        fcgi_res = self.collector.assess_fastcgi("vulnerable-dev.corp.internal")
        self.assertEqual(fcgi_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(fcgi_res.can_execute_code)
        self.assertTrue(any(c.finding_type == "fastcgi_rce" for c in fcgi_res.privilege_candidates))

    def test_code_execution_gating_unauthorized(self):
        strict_collector = OfflineSyntheticDeveloperCollector(
            targets=self.mock_services,
            allow_code_execution=False,
            allow_state_change=False,
        )
        res = strict_collector.assess_docker("vulnerable-dev.corp.internal", canary_artifact="canary_docker")
        self.assertFalse(res.can_execute_code)
        self.assertIn("Code execution verification skipped: not authorized in active action plan", res.uncertainty_notes)

    def test_protected_service_assessment(self):
        docker_res = self.collector.assess_docker("hardened-dev.corp.internal", canary_artifact="canary_docker_check")
        self.assertEqual(docker_res.exposure_status, DeveloperExposureStatus.PROTECTED.value)
        self.assertEqual(docker_res.auth_prerequisite, DeveloperAuthPrerequisite.CLIENT_CERT.value)
        self.assertEqual(len(docker_res.privilege_candidates), 0)
        self.assertEqual(len(docker_res.cleanup_receipts), 1)
        self.assertEqual(docker_res.cleanup_receipts[0].action_taken, "verified_removed")

        ajp_res = self.collector.assess_ajp("hardened-dev.corp.internal")
        self.assertEqual(ajp_res.exposure_status, DeveloperExposureStatus.PROTECTED.value)
        self.assertEqual(len(ajp_res.privilege_candidates), 0)

    def test_remediated_service_assessment(self):
        fcgi_res = self.collector.assess_fastcgi("remediated-dev.corp.internal")
        self.assertEqual(fcgi_res.exposure_status, DeveloperExposureStatus.REMEDIATED.value)
        self.assertEqual(len(fcgi_res.privilege_candidates), 0)

    def test_inaccessible_truth_boundary(self):
        res = self.collector.assess_docker("firewalled-host.corp.internal")
        self.assertEqual(res.exposure_status, DeveloperExposureStatus.INACCESSIBLE.value)
        self.assertEqual(res.auth_prerequisite, DeveloperAuthPrerequisite.UNKNOWN.value)
        self.assertFalse(res.canary_validated)
        self.assertIn("Service was inaccessible from probe vantage; this cannot be reported as secure or hardened", res.uncertainty_notes[0])

    def test_assess_developer_services_runner(self):
        report = assess_developer_services(
            targets=["vulnerable-dev.corp.internal", "hardened-dev.corp.internal"],
            service_types=["docker", "jdwp", "ajp"],
            collector=self.collector,
            vantage="internal",
            canary_id="canary_dev_test",
            allow_code_execution=True,
            allow_state_change=True,
        )
        self.assertIsInstance(report, DeveloperServicesReport)
        self.assertEqual(report.total_probed, 6)
        self.assertGreater(report.candidates_count, 0)
        self.assertGreater(report.cleanup_receipts_count, 0)

    def test_cli_developer_discovery_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            targets_file = tmp_path / "mock_targets.json"
            targets_file.write_text(json.dumps(self.mock_services), encoding="utf-8")

            report_file = tmp_path / "report.json"
            cand_file = tmp_path / "candidates.json"
            clean_file = tmp_path / "cleanup.json"

            # 1. Assess
            args_assess = argparse.Namespace(
                developer_command="assess",
                targets="vulnerable-dev.corp.internal,hardened-dev.corp.internal",
                services="docker,jdwp,distcc,ajp",
                vantage="internal",
                scope_ref="test-scope",
                canary_id="canary_run_probe",
                allow_code_execution=True,
                allow_state_change=True,
                mode="synthetic",
                offline_targets=str(targets_file),
                output=str(report_file),
            )
            ret = command_developer_discovery(args_assess)
            self.assertEqual(ret, 0)
            self.assertTrue(report_file.is_file())

            # 2. Candidates
            args_cand = argparse.Namespace(
                developer_command="candidates",
                report=str(report_file),
                output=str(cand_file),
            )
            ret = command_developer_discovery(args_cand)
            self.assertEqual(ret, 0)
            self.assertTrue(cand_file.is_file())
            candidates = json.loads(cand_file.read_text(encoding="utf-8"))
            self.assertGreater(len(candidates), 0)

            # 3. Cleanup
            args_clean = argparse.Namespace(
                developer_command="cleanup",
                report=str(report_file),
                output=str(clean_file),
            )
            ret = command_developer_discovery(args_clean)
            self.assertEqual(ret, 0)
            self.assertTrue(clean_file.is_file())
            receipts = json.loads(clean_file.read_text(encoding="utf-8"))
            self.assertGreater(len(receipts), 0)

            # 4. Inspect
            args_insp = argparse.Namespace(
                developer_command="inspect",
                report=str(report_file),
                json=True,
            )
            ret = command_developer_discovery(args_insp)
            self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
