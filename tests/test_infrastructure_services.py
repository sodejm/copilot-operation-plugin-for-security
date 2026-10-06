# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Unit, contract, and CLI tests for infrastructure and identity-facing services assessment."""

from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    AuthPrerequisite,
    IdentityAttackPathCandidate,
    IdentityAttackPathType,
    InfraAssessmentReport,
    InfraServiceAssessment,
    InfraServiceType,
    OfflineSyntheticInfraCollector,
    ServiceExposureStatus,
    assess_infrastructure_services,
)
from cops.discovery.cli import (
    command_infra_discovery,
)


class TestInfrastructureModelsAndSerialization(unittest.TestCase):
    def test_identity_attack_path_candidate_post_init_and_serialization(self):
        cand = IdentityAttackPathCandidate(
            candidate_id="cand-001",
            service_type="ldap",
            target_host="dc01.corp.internal",
            port=389,
            vantage="internal",
            attack_path_type=IdentityAttackPathType.LDAP_ANONYMOUS_RECONNAISSANCE.value,
            auth_prerequisites=AuthPrerequisite.NONE.value,
            ad_domain_realm="DC=corp,DC=internal",
        )
        self.assertTrue(cand.evidence_hash)
        self.assertIn("Disable LDAP anonymous binds", cand.remediation_guidance)
        d = cand.to_dict()
        reconstructed = IdentityAttackPathCandidate.from_dict(d)
        self.assertEqual(reconstructed.candidate_id, cand.candidate_id)
        self.assertEqual(reconstructed.evidence_hash, cand.evidence_hash)
        self.assertEqual(reconstructed.remediation_guidance, cand.remediation_guidance)

    def test_infra_service_assessment_serialization_roundtrip(self):
        cand = IdentityAttackPathCandidate(
            candidate_id="cand-002",
            service_type="kerberos",
            target_host="dc01.corp.internal",
            port=88,
            vantage="internal",
            attack_path_type=IdentityAttackPathType.ASREP_ROASTING.value,
            auth_prerequisites=AuthPrerequisite.KERBEROS_PREAUTH_DISABLED.value,
            target_principal="svc_backup@CORP.INTERNAL",
            ad_domain_realm="CORP.INTERNAL",
        )
        ass = InfraServiceAssessment(
            target_host="dc01.corp.internal",
            resolved_ip="198.51.100.10",
            service_type="kerberos",
            port=88,
            protocol="tcp",
            vantage="internal",
            exposure_status=ServiceExposureStatus.EXPOSED.value,
            canary_validated=True,
            canary_identifier="canary-user@CORP.INTERNAL",
            authentication_required=False,
            auth_prerequisite=AuthPrerequisite.KERBEROS_PREAUTH_DISABLED.value,
            applicable_versions=["Windows Kerberos 2019"],
            configuration_details={"realm": "CORP.INTERNAL"},
            observed_vulnerabilities=["Pre-authentication disabled for svc_backup"],
            attack_path_candidate=cand,
        )
        d = ass.to_dict()
        reconstructed = InfraServiceAssessment.from_dict(d)
        self.assertEqual(reconstructed.target_host, "dc01.corp.internal")
        self.assertEqual(reconstructed.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(len(reconstructed.attack_path_candidates), 1)
        self.assertEqual(reconstructed.attack_path_candidates[0].target_principal, "svc_backup@CORP.INTERNAL")

    def test_infra_assessment_report_save_and_properties(self):
        ass = InfraServiceAssessment(
            target_host="dc01.corp.internal",
            resolved_ip="198.51.100.10",
            service_type="ldap",
            port=389,
            exposure_status=ServiceExposureStatus.EXPOSED.value,
        )
        report = InfraAssessmentReport(
            report_id="infra-test-001",
            scope_reference="ROE-2026",
            services_assessed=[ass],
            summary={"total_services": 1, "exposed": 1},
        )
        self.assertEqual(report.total_assessed, 1)
        self.assertEqual(report.total_exposed, 1)
        self.assertEqual(report.total_inaccessible, 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.json"
            report.save(out_file)
            self.assertTrue(out_file.exists())
            with open(out_file, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["report_id"], "infra-test-001")


class TestInfrastructureCollectorsAndProtocols(unittest.TestCase):
    def setUp(self):
        self.service_db = {
            "dc01.corp.internal": {
                "dns": {
                    "open_recursion": True,
                    "version": "Microsoft DNS 10.0",
                    "canary_resolved": True,
                },
                "snmp": {
                    "community_strings": ["public"],
                    "sys_descr": "Linux enterprise-gw 5.15.0-generic",
                },
                "ntp": {
                    "monlist_enabled": True,
                    "version": "ntpd 4.2.6",
                    "amplification_factor": 25.5,
                },
                "rpc": {
                    "interfaces": [
                        {"uuid": "12345778-1234-abcd-ef00-0123456789ac", "name": "SAMR"},
                        {"uuid": "367abb81-9844-35f1-ad32-98f038001003", "name": "LSARPC"},
                    ],
                },
                "ldap": {
                    "anonymous_root_dse": True,
                    "naming_contexts": ["DC=corp,DC=internal"],
                    "supported_sasl": ["GSSAPI"],
                },
                "kerberos": {
                    "realm": "CORP.INTERNAL",
                    "preauth_disabled_accounts": ["svc_backup", "svc_sql"],
                    "canary_user_preauth_required": True,
                },
            },
            "hardened.corp.internal": {
                "dns": {"open_recursion": False},
                "snmp": {"community_strings": []},
                "ntp": {"monlist_enabled": False},
                "rpc": {"interfaces": []},
                "ldap": {"anonymous_root_dse": False},
                "kerberos": {"preauth_disabled_accounts": [], "realm": "CORP.INTERNAL"},
            },
            "filtered.corp.internal": {
                "dns": {"state": "filtered"},
                "snmp": {"inaccessible": True},
                "ntp": {"state": "timeout"},
                "rpc": {"state": "closed"},
                "ldap": {"inaccessible": True},
                "kerberos": {"state": "filtered"},
            },
            "offline-host.corp.internal": {
                "unreachable": True,
            },
        }
        self.collector = OfflineSyntheticInfraCollector(service_db=self.service_db)

    def test_dns_open_recursion_assessment(self):
        ass = self.collector.assess_dns("dc01.corp.internal", canary_id="canary.corp.internal")
        self.assertEqual(ass.service_type, InfraServiceType.DNS.value)
        self.assertEqual(ass.exposure_status, ServiceExposureStatus.MISCONFIGURED.value)
        self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.NONE.value)
        self.assertTrue(ass.canary_validated)
        self.assertEqual(len(ass.attack_path_candidates), 1)
        self.assertEqual(
            ass.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.OPEN_DNS_RECURSION.value,
        )

    def test_snmp_credential_leak_assessment(self):
        ass = self.collector.assess_snmp("dc01.corp.internal")
        self.assertEqual(ass.service_type, InfraServiceType.SNMP.value)
        self.assertEqual(ass.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.DEFAULT_CREDENTIALS.value)
        self.assertEqual(len(ass.attack_path_candidates), 1)
        self.assertEqual(
            ass.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.SNMP_CREDENTIAL_LEAK.value,
        )

    def test_ntp_monlist_amplification_assessment(self):
        ass = self.collector.assess_ntp("dc01.corp.internal")
        self.assertEqual(ass.service_type, InfraServiceType.NTP.value)
        self.assertEqual(ass.exposure_status, ServiceExposureStatus.MISCONFIGURED.value)
        self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.NONE.value)
        self.assertEqual(len(ass.attack_path_candidates), 1)
        self.assertEqual(
            ass.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.NTP_MODE6_AMPLIFICATION.value,
        )

    def test_rpc_endpoint_mapper_interfaces(self):
        ass = self.collector.assess_rpc("dc01.corp.internal")
        self.assertEqual(ass.service_type, InfraServiceType.RPC.value)
        self.assertEqual(ass.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.NONE.value)
        self.assertEqual(len(ass.attack_path_candidates), 1)
        self.assertEqual(
            ass.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.RPC_ENDPOINT_ENUMERATION.value,
        )

    def test_ldap_anonymous_root_dse_assessment(self):
        ass = self.collector.assess_ldap("dc01.corp.internal")
        self.assertEqual(ass.service_type, InfraServiceType.LDAP.value)
        self.assertEqual(ass.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.NONE.value)
        self.assertEqual(len(ass.attack_path_candidates), 1)
        self.assertEqual(
            ass.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.LDAP_ANONYMOUS_RECONNAISSANCE.value,
        )
        self.assertEqual(ass.attack_path_candidates[0].ad_domain_realm, "DC=corp,DC=internal")

    def test_kerberos_preauth_candidates_multiple_accounts(self):
        ass = self.collector.assess_kerberos("dc01.corp.internal")
        self.assertEqual(ass.service_type, InfraServiceType.KERBEROS.value)
        self.assertEqual(ass.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.KERBEROS_PREAUTH_DISABLED.value)
        candidates = ass.attack_path_candidates
        self.assertEqual(len(candidates), 2)
        principals = [c.target_principal for c in candidates]
        self.assertIn("svc_backup@CORP.INTERNAL", principals)
        self.assertIn("svc_sql@CORP.INTERNAL", principals)

    def test_hardened_services_report_protected(self):
        ass = self.collector.assess_ldap("hardened.corp.internal")
        self.assertEqual(ass.exposure_status, ServiceExposureStatus.PROTECTED.value)
        self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.DOMAIN_USER.value)
        self.assertEqual(len(ass.attack_path_candidates), 0)

        dns_ass = self.collector.assess_dns("hardened.corp.internal")
        self.assertEqual(dns_ass.exposure_status, ServiceExposureStatus.PROTECTED.value)

    def test_inaccessible_services_never_reported_as_secure(self):
        """CRITICAL TRUTH BOUNDARY: An inaccessible service must NEVER be reported as protected or hardened."""
        for svc in ("dns", "snmp", "ntp", "rpc", "ldap", "kerberos"):
            fn = getattr(self.collector, f"assess_{svc}")
            ass = fn("filtered.corp.internal")
            self.assertEqual(
                ass.exposure_status,
                ServiceExposureStatus.INACCESSIBLE.value,
                f"Service {svc} on filtered target should be INACCESSIBLE, not {ass.exposure_status}",
            )
            self.assertNotEqual(ass.exposure_status, ServiceExposureStatus.PROTECTED.value)
            self.assertEqual(ass.auth_prerequisite, AuthPrerequisite.UNKNOWN.value)
            self.assertTrue(any("inaccessible" in n.lower() for n in ass.uncertainty_notes))

        # Unreachable host
        ass_unreachable = self.collector.assess_ldap("offline-host.corp.internal")
        self.assertEqual(ass_unreachable.exposure_status, ServiceExposureStatus.INACCESSIBLE.value)
        self.assertNotEqual(ass_unreachable.exposure_status, ServiceExposureStatus.PROTECTED.value)

    def test_assess_infrastructure_services_function(self):
        report = assess_infrastructure_services(
            targets=["dc01.corp.internal", "hardened.corp.internal", "filtered.corp.internal"],
            collector=self.collector,
            vantage="internal",
            scope_ref="ROE-INFRA-01",
        )
        self.assertEqual(report.scope_reference, "ROE-INFRA-01")
        self.assertGreater(report.total_assessed, 0)
        self.assertGreater(report.total_exposed, 0)
        self.assertGreater(report.total_protected, 0)
        self.assertGreater(report.total_inaccessible, 0)
        self.assertGreater(len(report.all_attack_path_candidates), 0)


class TestInfrastructureCLI(unittest.TestCase):
    def setUp(self):
        self.service_db = {
            "dc01.corp.internal": {
                "ldap": {
                    "anonymous_root_dse": True,
                    "naming_contexts": ["DC=corp,DC=internal"],
                },
                "kerberos": {
                    "realm": "CORP.INTERNAL",
                    "preauth_disabled_accounts": ["svc_backup"],
                },
            },
            "unreachable.corp.internal": {
                "unreachable": True,
            },
        }

    def test_cli_assess_and_candidates_and_inspect(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "infra_report.json"
            cand_path = Path(tmpdir) / "candidates.json"

            targets_file = Path(tmpdir) / "mock_targets.json"
            targets_file.write_text(json.dumps(self.service_db), encoding="utf-8")

            # 1. Test Assess
            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers(dest="command")
            from cops.discovery.cli import build_discovery_parser
            build_discovery_parser(subparsers)

            # Assess
            args = parser.parse_args([
                "discovery", "infrastructure", "assess",
                "--targets", "dc01.corp.internal,unreachable.corp.internal",
                "--services", "ldap,kerberos",
                "--offline-targets", str(targets_file),
                "--vantage", "internal",
                "--output", str(report_path),
            ])
            rc = command_infra_discovery(args)
            self.assertEqual(rc, 0)
            self.assertTrue(report_path.exists())

            # 2. Test Candidates Extraction
            args_cand = parser.parse_args([
                "discovery", "infrastructure", "candidates",
                str(report_path),
                "--output", str(cand_path),
            ])
            rc_cand = command_infra_discovery(args_cand)
            self.assertEqual(rc_cand, 0)
            self.assertTrue(cand_path.exists())

            with open(cand_path, encoding="utf-8") as f:
                cands_data = json.load(f)
            self.assertIsInstance(cands_data, list)
            self.assertGreater(len(cands_data), 0)

            # 3. Test Inspect
            args_inspect = parser.parse_args([
                "discovery", "infrastructure", "inspect",
                str(report_path),
            ])
            buf = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = buf
                rc_insp = command_infra_discovery(args_inspect)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc_insp, 0)
            output = buf.getvalue()
            self.assertIn("Infrastructure & Identity Services Report", output)
            self.assertIn("Truth-in-Advertising Notice", output)


if __name__ == "__main__":
    unittest.main()
