"""Tests for network-infrastructure-services contributor skill."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    AuthPrerequisite,
    IdentityAttackPathType,
    InfraServiceAssessment,
    InfraServiceType,
    OfflineSyntheticInfraCollector,
    ServiceExposureStatus,
    assess_infrastructure_services,
)


class TestNetworkInfrastructureServicesSkill(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "dc01.corp.internal": {
                "dns": {
                    "open_recursion": True,
                    "version": "Windows DNS 10.0.17763",
                    "canary_resolved": True,
                },
                "snmp": {
                    "community_strings": ["public"],
                    "sys_descr": "Hardware: Intel64 Family 6 - Software: Windows Version 10.0",
                },
                "ntp": {
                    "monlist_enabled": True,
                    "version": "ntpd 4.2.8p15",
                },
                "rpc": {
                    "interfaces": [
                        {"uuid": "12345778-1234-abcd-ef00-0123456789ac", "name": "SAMR"},
                        {"uuid": "367abb81-9844-35f1-ad32-98f038001003", "name": "LSARPC"},
                    ],
                },
                "ldap": {
                    "anonymous_root_dse": True,
                    "naming_contexts": ["DC=corp,DC=internal", "CN=Configuration,DC=corp,DC=internal"],
                    "supported_sasl": ["GSSAPI", "GSS-SPNEGO"],
                },
                "kerberos": {
                    "realm": "CORP.INTERNAL",
                    "preauth_disabled_accounts": ["svc_backup", "svc_sql"],
                    "canary_user_preauth_required": True,
                },
            },
            "hardened-dc.corp.internal": {
                "dns": {
                    "open_recursion": False,
                    "version": "Windows DNS",
                },
                "snmp": {
                    "community_strings": [],
                },
                "ntp": {
                    "monlist_enabled": False,
                },
                "rpc": {
                    "interfaces": [],
                },
                "ldap": {
                    "anonymous_root_dse": False,
                },
                "kerberos": {
                    "realm": "CORP.INTERNAL",
                    "preauth_disabled_accounts": [],
                },
            },
            "unreachable.corp.internal": {
                # Empty or missing protocols simulate inaccessible/filtered targets
            },
        }
        self.collector = OfflineSyntheticInfraCollector(service_db=self.mock_services)

    def test_dns_assessment_and_recursion_detection(self):
        assessment = self.collector.assess_dns("dc01.corp.internal")
        self.assertEqual(assessment.service_type, InfraServiceType.DNS.value)
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.MISCONFIGURED.value)
        self.assertEqual(assessment.auth_prerequisite, AuthPrerequisite.NONE.value)
        self.assertTrue(assessment.protocol_details.get("open_recursion"))
        self.assertTrue(assessment.canary_validated)
        self.assertGreater(len(assessment.attack_path_candidates), 0)
        self.assertEqual(
            assessment.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.OPEN_DNS_RECURSION.value,
        )

    def test_snmp_default_community_detection(self):
        assessment = self.collector.assess_snmp("dc01.corp.internal")
        self.assertEqual(assessment.service_type, InfraServiceType.SNMP.value)
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(assessment.auth_prerequisite, AuthPrerequisite.DEFAULT_CREDENTIALS.value)
        self.assertIn("public", assessment.protocol_details.get("community_strings", []))
        self.assertEqual(
            assessment.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.SNMP_CREDENTIAL_LEAK.value,
        )

    def test_ntp_monlist_amplification_assessment(self):
        assessment = self.collector.assess_ntp("dc01.corp.internal")
        self.assertEqual(assessment.service_type, InfraServiceType.NTP.value)
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.MISCONFIGURED.value)
        self.assertTrue(assessment.protocol_details.get("monlist_enabled"))
        self.assertEqual(
            assessment.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.NTP_MODE6_AMPLIFICATION.value,
        )

    def test_rpc_endpoint_mapper_enumeration(self):
        assessment = self.collector.assess_rpc("dc01.corp.internal")
        self.assertEqual(assessment.service_type, InfraServiceType.RPC.value)
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(assessment.auth_prerequisite, AuthPrerequisite.NONE.value)
        self.assertEqual(len(assessment.protocol_details.get("interfaces", [])), 2)
        self.assertEqual(
            assessment.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.RPC_ENDPOINT_ENUMERATION.value,
        )

    def test_ldap_root_dse_anonymous_reconnaissance(self):
        assessment = self.collector.assess_ldap("dc01.corp.internal")
        self.assertEqual(assessment.service_type, InfraServiceType.LDAP.value)
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(assessment.auth_prerequisite, AuthPrerequisite.NONE.value)
        self.assertTrue(assessment.protocol_details.get("anonymous_root_dse"))
        self.assertIn("DC=corp,DC=internal", assessment.protocol_details.get("naming_contexts", []))
        self.assertEqual(
            assessment.attack_path_candidates[0].attack_path_type,
            IdentityAttackPathType.LDAP_ANONYMOUS_RECONNAISSANCE.value,
        )

    def test_kerberos_asrep_roasting_candidates(self):
        assessment = self.collector.assess_kerberos("dc01.corp.internal")
        self.assertEqual(assessment.service_type, InfraServiceType.KERBEROS.value)
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.EXPOSED.value)
        self.assertEqual(assessment.auth_prerequisite, AuthPrerequisite.KERBEROS_PREAUTH_DISABLED.value)
        candidates = assessment.attack_path_candidates
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].target_principal, "svc_backup@CORP.INTERNAL")
        self.assertEqual(candidates[0].attack_path_type, IdentityAttackPathType.ASREP_ROASTING.value)
        self.assertTrue(assessment.canary_validated)

    def test_inaccessible_service_is_never_reported_as_secure(self):
        """CRITICAL TRUTH BOUNDARY: An inaccessible (timed out/closed) service must NEVER be reported as protected or hardened."""
        assessment = self.collector.assess_ldap("unreachable.corp.internal")
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.INACCESSIBLE.value)
        self.assertNotEqual(assessment.exposure_status, ServiceExposureStatus.PROTECTED.value)
        self.assertEqual(assessment.auth_prerequisite, AuthPrerequisite.UNKNOWN.value)
        self.assertIn("inaccessible", " ".join(assessment.uncertainty_notes).lower())

        dns_assessment = self.collector.assess_dns("unreachable.corp.internal")
        self.assertEqual(dns_assessment.exposure_status, ServiceExposureStatus.INACCESSIBLE.value)
        self.assertEqual(dns_assessment.auth_prerequisite, AuthPrerequisite.UNKNOWN.value)

    def test_hardened_services_reported_as_protected(self):
        """When a service actively denies unauthenticated access or is properly hardened, report protected."""
        assessment = self.collector.assess_ldap("hardened-dc.corp.internal")
        self.assertEqual(assessment.exposure_status, ServiceExposureStatus.PROTECTED.value)
        self.assertEqual(assessment.auth_prerequisite, AuthPrerequisite.DOMAIN_USER.value)
        self.assertEqual(len(assessment.attack_path_candidates), 0)

    def test_comprehensive_assessment_report_generation(self):
        report = assess_infrastructure_services(
            targets=["dc01.corp.internal", "unreachable.corp.internal"],
            collector=self.collector,
            vantage="internal",
        )
        self.assertGreater(report.total_assessed, 0)
        self.assertGreater(report.total_exposed, 0)
        self.assertGreater(report.total_inaccessible, 0)
        candidates = report.all_attack_path_candidates
        self.assertGreater(len(candidates), 0)

        # Verify candidate dictionary conversion
        cand_dicts = [c.to_dict() for c in candidates]
        self.assertTrue(all("evidence_hash" in d for d in cand_dicts))
        self.assertTrue(all("remediation_guidance" in d for d in cand_dicts))


if __name__ == "__main__":
    unittest.main()
