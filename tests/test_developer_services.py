"""Unit, contract, and CLI tests for developer and runtime interfaces assessment."""

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
    DEFAULT_DEVELOPER_PORTS,
    DeveloperAuthPrerequisite,
    DeveloperCategory,
    DeveloperExposureStatus,
    DeveloperPrivilegeCandidate,
    DeveloperPrivilegeImpact,
    DeveloperServiceAssessment,
    DeveloperServicesCollector,
    DeveloperServicesReport,
    DeveloperServiceType,
    ExecutionEffect,
    OfflineSyntheticDeveloperCollector,
    StandardSocketDeveloperCollector,
    assess_developer_services,
)
from cops.discovery.cli import command_developer_discovery


class TestDeveloperModelsAndSerialization(unittest.TestCase):
    def test_developer_privilege_candidate_post_init_and_serialization(self):
        cand = DeveloperPrivilegeCandidate(
            candidate_id="cand-docker-01",
            service_type="docker",
            category="container_orchestration_runtime",
            target_host="dev01.corp.internal",
            port=2375,
            vantage="external",
            finding_type="docker_socket_rce",
            auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
            privilege_impact=DeveloperPrivilegeImpact.CONTAINER_ESCAPE.value,
            execution_effect=ExecutionEffect.CODE_EXECUTION.value,
        )
        self.assertTrue(cand.evidence_hash)
        self.assertIn("Docker daemon strictly to local Unix socket", cand.remediation_guidance)
        d = cand.to_dict()
        reconstructed = DeveloperPrivilegeCandidate.from_dict(d)
        self.assertEqual(reconstructed.candidate_id, cand.candidate_id)
        self.assertEqual(reconstructed.evidence_hash, cand.evidence_hash)
        self.assertEqual(reconstructed.remediation_guidance, cand.remediation_guidance)
        self.assertEqual(reconstructed.privilege_impact, DeveloperPrivilegeImpact.CONTAINER_ESCAPE.value)
        self.assertEqual(reconstructed.execution_effect, ExecutionEffect.CODE_EXECUTION.value)

    def test_cleanup_receipt_post_init_and_serialization(self):
        receipt = CleanupReceipt(
            receipt_id="rec-dev-001",
            target_host="dev01.corp.internal",
            service_type="docker",
            artifact_type="canary_container",
            artifact_identifier="cops_canary_test_container",
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

    def test_developer_service_assessment_serialization(self):
        cand = DeveloperPrivilegeCandidate(
            candidate_id="cand-jdwp-01",
            service_type="jdwp",
            category="language_debug_runtime",
            target_host="dev01.corp.internal",
            port=8000,
            finding_type="jdwp_code_execution",
            execution_effect=ExecutionEffect.CODE_EXECUTION.value,
        )
        receipt = CleanupReceipt(
            receipt_id="rec-jdwp-01",
            target_host="dev01.corp.internal",
            service_type="jdwp",
            artifact_type="canary_breakpoint",
            artifact_identifier="canary_jdwp_bp",
        )
        ass = DeveloperServiceAssessment(
            target_host="dev01.corp.internal",
            resolved_ip="198.51.100.50",
            service_type="jdwp",
            category="language_debug_runtime",
            port=8000,
            exposure_status=DeveloperExposureStatus.EXPOSED.value,
            canary_validated=True,
            canary_identifier="canary_jdwp_bp",
            authentication_required=False,
            auth_prerequisite=DeveloperAuthPrerequisite.NONE.value,
            can_execute_code=True,
            can_change_state=False,
            bound_to_plan=True,
            privilege_candidates=[cand],
            cleanup_receipts=[receipt],
        )
        d = ass.to_dict()
        reconstructed = DeveloperServiceAssessment.from_dict(d)
        self.assertEqual(reconstructed.target_host, "dev01.corp.internal")
        self.assertEqual(reconstructed.port, 8000)
        self.assertEqual(reconstructed.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(reconstructed.can_execute_code)
        self.assertFalse(reconstructed.can_change_state)
        self.assertTrue(reconstructed.bound_to_plan)
        self.assertEqual(len(reconstructed.privilege_candidates), 1)
        self.assertEqual(len(reconstructed.cleanup_receipts), 1)

    def test_developer_services_report_serialization_and_disk_io(self):
        ass = DeveloperServiceAssessment(
            target_host="dev01.corp.internal",
            resolved_ip="198.51.100.50",
            service_type="docker",
            category="container_orchestration_runtime",
            port=2375,
            exposure_status=DeveloperExposureStatus.EXPOSED.value,
            can_execute_code=True,
        )
        report = DeveloperServicesReport(
            report_id="dev-rep-001",
            target_scope=["dev01.corp.internal"],
            vantage="internal",
            assessments=[ass],
            total_probed=1,
            total_exposed=1,
            candidates_count=0,
            cleanup_receipts_count=0,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "report.json"
            report.save(file_path)
            self.assertTrue(file_path.is_file())

            loaded = DeveloperServicesReport.load(file_path)
            self.assertEqual(loaded.report_id, report.report_id)
            self.assertEqual(loaded.total_probed, 1)
            self.assertEqual(loaded.assessments[0].service_type, "docker")
            self.assertTrue(loaded.assessments[0].can_execute_code)


class TestOfflineSyntheticDeveloperCollector(unittest.TestCase):
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
        self.assertTrue(result.can_change_state)
        self.assertGreaterEqual(len(result.privilege_candidates), 1)
        cand = result.privilege_candidates[0]
        self.assertEqual(cand.finding_type, "docker_socket_rce")
        self.assertEqual(cand.execution_effect, ExecutionEffect.CODE_EXECUTION.value)
        self.assertEqual(cand.privilege_impact, DeveloperPrivilegeImpact.CONTAINER_ESCAPE.value)

    def test_assess_docker_registry_vulnerabilities(self):
        result = self.collector.assess_docker_registry("vulnerable-dev.corp.internal", canary_artifact="canary_repo")
        self.assertEqual(result.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(result.canary_validated)
        self.assertFalse(result.can_execute_code)
        cand = result.privilege_candidates[0]
        self.assertEqual(cand.finding_type, "docker_registry_leak")
        self.assertEqual(cand.execution_effect, ExecutionEffect.READ_ONLY.value)
        self.assertEqual(cand.privilege_impact, DeveloperPrivilegeImpact.SOURCE_CODE_LEAKAGE.value)

    def test_assess_rmi_and_jdwp_vulnerabilities(self):
        rmi_res = self.collector.assess_rmi("vulnerable-dev.corp.internal")
        self.assertEqual(rmi_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(rmi_res.can_execute_code)
        self.assertTrue(any(c.finding_type == "rmi_code_execution" for c in rmi_res.privilege_candidates))

        jdwp_res = self.collector.assess_jdwp("vulnerable-dev.corp.internal", canary_artifact="canary_jdwp_bp")
        self.assertEqual(jdwp_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(jdwp_res.can_execute_code)
        self.assertTrue(any(c.finding_type == "jdwp_code_execution" for c in jdwp_res.privilege_candidates))

    def test_assess_erlang_epmd_and_adb_vulnerabilities(self):
        epmd_res = self.collector.assess_erlang_epmd("vulnerable-dev.corp.internal")
        self.assertEqual(epmd_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(epmd_res.can_execute_code)
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
        self.assertFalse(svn_res.can_execute_code)
        self.assertTrue(any(c.finding_type == "svn_anonymous_checkout" for c in svn_res.privilege_candidates))

    def test_assess_ajp_and_fastcgi_vulnerabilities(self):
        ajp_res = self.collector.assess_ajp("vulnerable-dev.corp.internal")
        self.assertEqual(ajp_res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(ajp_res.can_execute_code)
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
        self.assertFalse(res.can_change_state)
        self.assertIn("Code execution verification skipped: not authorized in active action plan", res.uncertainty_notes)
        self.assertIn("State change verification skipped: not authorized in active action plan", res.uncertainty_notes)

    def test_protected_service_assessment(self):
        docker_res = self.collector.assess_docker("hardened-dev.corp.internal", canary_artifact="canary_docker_check")
        self.assertEqual(docker_res.exposure_status, DeveloperExposureStatus.PROTECTED.value)
        self.assertEqual(docker_res.auth_prerequisite, DeveloperAuthPrerequisite.CLIENT_CERT.value)
        self.assertEqual(len(docker_res.privilege_candidates), 0)
        self.assertEqual(len(docker_res.cleanup_receipts), 1)
        self.assertEqual(docker_res.cleanup_receipts[0].action_taken, "verified_removed")

        registry_res = self.collector.assess_docker_registry("hardened-dev.corp.internal")
        self.assertEqual(registry_res.exposure_status, DeveloperExposureStatus.PROTECTED.value)
        self.assertEqual(registry_res.auth_prerequisite, DeveloperAuthPrerequisite.TOKEN_OR_API_KEY.value)

        jdwp_res = self.collector.assess_jdwp("hardened-dev.corp.internal")
        self.assertEqual(jdwp_res.exposure_status, DeveloperExposureStatus.PROTECTED.value)

        ajp_res = self.collector.assess_ajp("hardened-dev.corp.internal")
        self.assertEqual(ajp_res.exposure_status, DeveloperExposureStatus.PROTECTED.value)

    def test_remediated_service_assessment(self):
        fcgi_res = self.collector.assess_fastcgi("remediated-dev.corp.internal")
        self.assertEqual(fcgi_res.exposure_status, DeveloperExposureStatus.REMEDIATED.value)
        self.assertEqual(len(fcgi_res.privilege_candidates), 0)


class TestTruthBoundaryAndInaccessibleHandling(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "firewalled-host.corp.internal": {
                "docker": {"state": "filtered"},
                "jdwp": {"state": "timeout"},
                "ajp": {"inaccessible": True},
            },
            "unreachable-host.corp.internal": {
                "unreachable": True,
            },
        }
        self.collector = OfflineSyntheticDeveloperCollector(targets=self.mock_services)

    def test_inaccessible_filtered_service(self):
        res = self.collector.assess_docker("firewalled-host.corp.internal")
        self.assertEqual(res.exposure_status, DeveloperExposureStatus.INACCESSIBLE.value)
        self.assertEqual(res.auth_prerequisite, DeveloperAuthPrerequisite.UNKNOWN.value)
        self.assertFalse(res.canary_validated)
        self.assertIn("Service was inaccessible from probe vantage; this cannot be reported as secure or hardened", res.uncertainty_notes[0])
        self.assertEqual(len(res.privilege_candidates), 0)

    def test_inaccessible_timeout_service(self):
        res = self.collector.assess_jdwp("firewalled-host.corp.internal")
        self.assertEqual(res.exposure_status, DeveloperExposureStatus.INACCESSIBLE.value)
        self.assertEqual(res.auth_prerequisite, DeveloperAuthPrerequisite.UNKNOWN.value)

    def test_inaccessible_unreachable_target(self):
        res = self.collector.assess_ajp("unreachable-host.corp.internal")
        self.assertEqual(res.exposure_status, DeveloperExposureStatus.INACCESSIBLE.value)
        self.assertEqual(res.auth_prerequisite, DeveloperAuthPrerequisite.UNKNOWN.value)


class TestRunnerAndReportAggregation(unittest.TestCase):
    def test_assess_developer_services_runner(self):
        mock_targets = {
            "dev01.corp.internal": {
                "docker": {"socket_exposed": True, "tls_verify": False, "auth_required": False},
                "jdwp": {"debug_agent_exposed": True, "auth_required": False},
            },
            "dev02.corp.internal": {
                "docker": {"protected": True, "tls_verify": True, "auth_required": True},
                "jdwp": {"state": "filtered"},
            },
        }
        collector = OfflineSyntheticDeveloperCollector(
            targets=mock_targets,
            allow_code_execution=True,
            allow_state_change=True,
        )
        report = assess_developer_services(
            targets=["dev01.corp.internal", "dev02.corp.internal"],
            service_types=["docker", "jdwp"],
            collector=collector,
            vantage="internal",
            canary_id="canary_runner_test",
            allow_code_execution=True,
            allow_state_change=True,
        )
        self.assertEqual(report.total_probed, 4)
        self.assertEqual(report.total_exposed, 2)
        self.assertEqual(report.total_protected, 1)
        self.assertEqual(report.total_inaccessible, 1)
        self.assertGreater(report.candidates_count, 0)
        self.assertGreater(report.cleanup_receipts_count, 0)


class TestCLIDeveloperCommands(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "dev-cli.corp.internal": {
                "docker": {"socket_exposed": True, "tls_verify": False, "auth_required": False},
                "jdwp": {"debug_agent_exposed": True, "auth_required": False},
            },
            "hardened-cli.corp.internal": {
                "docker": {"protected": True, "tls_verify": True, "auth_required": True},
            },
        }

    def test_cli_lifecycle(self):
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
                targets="dev-cli.corp.internal,hardened-cli.corp.internal",
                services="docker,jdwp",
                vantage="internal",
                scope_ref="cli-scope",
                canary_id="canary_cli_probe",
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

            # 4. Inspect JSON
            args_insp_json = argparse.Namespace(
                developer_command="inspect",
                report=str(report_file),
                json=True,
            )
            ret = command_developer_discovery(args_insp_json)
            self.assertEqual(ret, 0)

            # 5. Inspect Text
            args_insp_text = argparse.Namespace(
                developer_command="inspect",
                report=str(report_file),
                json=False,
            )
            ret = command_developer_discovery(args_insp_text)
            self.assertEqual(ret, 0)


class TestStandardSocketDeveloperCollectorMocked(unittest.TestCase):
    @patch("socket.create_connection")
    @patch("socket.gethostbyname")
    def test_socket_probe_connected(self, mock_gethost, mock_conn):
        mock_gethost.return_value = "198.51.100.50"
        mock_conn.return_value.__enter__.return_value = MagicMock()

        collector = StandardSocketDeveloperCollector(
            allow_code_execution=True,
            allow_state_change=True,
        )
        res = collector.assess_docker("dev.corp.internal", canary_artifact="canary_probe")
        self.assertEqual(res.exposure_status, DeveloperExposureStatus.EXPOSED.value)
        self.assertTrue(res.canary_validated)
        self.assertEqual(res.resolved_ip, "198.51.100.50")
        self.assertIn("TCP connect succeeded", res.uncertainty_notes[0])

    @patch("socket.create_connection")
    @patch("socket.gethostbyname")
    def test_socket_probe_connection_refused(self, mock_gethost, mock_conn):
        mock_gethost.return_value = "198.51.100.50"
        mock_conn.side_effect = ConnectionRefusedError("Connection refused")

        collector = StandardSocketDeveloperCollector()
        res = collector.assess_docker("dev.corp.internal")
        self.assertEqual(res.exposure_status, DeveloperExposureStatus.INACCESSIBLE.value)
        self.assertEqual(res.auth_prerequisite, DeveloperAuthPrerequisite.UNKNOWN.value)
        self.assertIn("Connection refused", res.error_message)


if __name__ == "__main__":
    unittest.main()
