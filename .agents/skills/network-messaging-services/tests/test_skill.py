"""Tests for network-messaging-services contributor skill."""

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
    MessagingAuthPrerequisite,
    MessagingCategory,
    MessagingExposureStatus,
    MessagingPrivilegeCandidate,
    MessagingPrivilegeImpact,
    MessagingServiceAssessment,
    MessagingServicesReport,
    MessagingServiceType,
    OfflineSyntheticMessagingCollector,
    assess_messaging_services,
)
from cops.discovery.cli import command_messaging_discovery


class TestNetworkMessagingServicesSkill(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "vulnerable-mail.corp.internal": {
                "smtp": {
                    "relay_allowed": True,
                    "user_enumeration_enabled": True,
                    "vrfy_supported": True,
                    "messages_sent": 2,
                    "version": "Postfix 3.4.13",
                },
                "pop3": {
                    "plaintext_auth_allowed": True,
                    "tls_enforced": False,
                    "version": "Dovecot 2.3.7",
                },
                "imap": {
                    "anonymous_allowed": True,
                    "auth_required": False,
                    "tls_enforced": False,
                    "version": "Dovecot 2.3.7",
                },
                "irc": {
                    "unauthenticated_oper": True,
                    "oper_password_required": False,
                    "version": "InspIRCd-3",
                },
                "rabbitmq": {
                    "guest_enabled": True,
                    "open_management": True,
                    "auth_required": False,
                    "version": "RabbitMQ 3.9.0",
                },
                "nats": {
                    "auth_required": False,
                    "version": "NATS 2.8.2",
                },
                "ibmmq": {
                    "blank_channel_enabled": True,
                    "mcauser_enforced": False,
                    "version": "IBM MQ 9.2",
                },
                "kafka": {
                    "sasl_enabled": False,
                    "auth_required": False,
                    "version": "Kafka 3.2.0",
                },
                "mqtt": {
                    "allow_anonymous": True,
                    "auth_required": False,
                    "version": "Mosquitto 2.0.11",
                },
            },
            "hardened-mail.corp.internal": {
                "smtp": {
                    "protected": True,
                    "starttls_enforced": True,
                    "relay_allowed": False,
                    "authentication_required": True,
                    "auth_prerequisite": MessagingAuthPrerequisite.USER_PASSWORD.value,
                    "version": "Postfix 3.6.4",
                },
                "rabbitmq": {
                    "protected": True,
                    "guest_enabled": False,
                    "auth_required": True,
                    "management_auth_required": True,
                    "auth_prerequisite": MessagingAuthPrerequisite.USER_PASSWORD.value,
                    "version": "RabbitMQ 3.10.0",
                },
            },
            "remediated-broker.corp.internal": {
                "kafka": {
                    "remediated": True,
                    "auth_prerequisite": MessagingAuthPrerequisite.SASL.value,
                    "role": "authenticated_client",
                    "version": "Kafka 3.4.0",
                }
            },
            "firewalled-host.corp.internal": {
                "smtp": {"state": "filtered"},
                "kafka": {"state": "timeout"},
            },
        }
        self.collector = OfflineSyntheticMessagingCollector(targets=self.mock_services)

    def test_assess_smtp_vulnerabilities(self):
        result = self.collector.assess_smtp("vulnerable-mail.corp.internal", canary_artifact="canary_mail_probe")
        self.assertEqual(result.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(result.canary_validated)
        self.assertEqual(result.canary_identifier, "canary_mail_probe")
        self.assertTrue(result.relay_permitted)
        self.assertGreaterEqual(len(result.privilege_candidates), 2)
        finding_types = [c.finding_type for c in result.privilege_candidates]
        self.assertIn("smtp_open_relay", finding_types)
        self.assertIn("smtp_user_enumeration", finding_types)

    def test_assess_pop3_and_imap_vulnerabilities(self):
        pop3_res = self.collector.assess_pop3("vulnerable-mail.corp.internal")
        self.assertEqual(pop3_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "pop3_plaintext_auth" for c in pop3_res.privilege_candidates))

        imap_res = self.collector.assess_imap("vulnerable-mail.corp.internal")
        self.assertEqual(imap_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "imap_anonymous_login" for c in imap_res.privilege_candidates))

    def test_assess_irc_vulnerability(self):
        irc_res = self.collector.assess_irc("vulnerable-mail.corp.internal")
        self.assertEqual(irc_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "irc_unauthenticated_operator" for c in irc_res.privilege_candidates))

    def test_assess_brokers_vulnerabilities(self):
        rabbit_res = self.collector.assess_rabbitmq("vulnerable-mail.corp.internal")
        self.assertEqual(rabbit_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        rabbit_findings = [c.finding_type for c in rabbit_res.privilege_candidates]
        self.assertIn("rabbitmq_guest_default_creds", rabbit_findings)
        self.assertIn("rabbitmq_open_management", rabbit_findings)

        nats_res = self.collector.assess_nats("vulnerable-mail.corp.internal")
        self.assertTrue(any(c.finding_type == "nats_unauthenticated_cluster" for c in nats_res.privilege_candidates))

        ibmmq_res = self.collector.assess_ibmmq("vulnerable-mail.corp.internal")
        self.assertTrue(any(c.finding_type == "ibmmq_blank_channel" for c in ibmmq_res.privilege_candidates))

        kafka_res = self.collector.assess_kafka("vulnerable-mail.corp.internal")
        self.assertTrue(any(c.finding_type == "kafka_unauthenticated_broker" for c in kafka_res.privilege_candidates))

        mqtt_res = self.collector.assess_mqtt("vulnerable-mail.corp.internal")
        self.assertTrue(any(c.finding_type == "mqtt_anonymous_read_write" for c in mqtt_res.privilege_candidates))

    def test_protected_service_assessment(self):
        smtp_res = self.collector.assess_smtp("hardened-mail.corp.internal", canary_artifact="canary_smtp_test")
        self.assertEqual(smtp_res.exposure_status, MessagingExposureStatus.PROTECTED.value)
        self.assertTrue(smtp_res.tls_enforced)
        self.assertFalse(smtp_res.relay_permitted)
        self.assertEqual(len(smtp_res.privilege_candidates), 0)
        self.assertEqual(len(smtp_res.cleanup_receipts), 1)
        self.assertEqual(smtp_res.cleanup_receipts[0].action_taken, "verified_removed")

        rabbit_res = self.collector.assess_rabbitmq("hardened-mail.corp.internal")
        self.assertEqual(rabbit_res.exposure_status, MessagingExposureStatus.PROTECTED.value)
        self.assertEqual(len(rabbit_res.privilege_candidates), 0)

    def test_remediated_service_assessment(self):
        kafka_res = self.collector.assess_kafka("remediated-broker.corp.internal", canary_artifact="canary_topic")
        self.assertEqual(kafka_res.exposure_status, MessagingExposureStatus.REMEDIATED.value)
        self.assertEqual(kafka_res.auth_prerequisite, MessagingAuthPrerequisite.SASL.value)
        self.assertEqual(len(kafka_res.privilege_candidates), 0)

    def test_inaccessible_truth_boundary(self):
        res = self.collector.assess_smtp("firewalled-host.corp.internal")
        self.assertEqual(res.exposure_status, MessagingExposureStatus.INACCESSIBLE.value)
        self.assertEqual(res.auth_prerequisite, MessagingAuthPrerequisite.UNKNOWN.value)
        self.assertFalse(res.canary_validated)
        self.assertIn("Service was inaccessible from probe vantage; this cannot be reported as secure or hardened", res.uncertainty_notes[0])

    def test_bounded_message_budget(self):
        res = self.collector.assess_smtp("vulnerable-mail.corp.internal", message_budget=3)
        self.assertLessEqual(res.messages_sent_or_observed, 3)

    def test_assess_messaging_services_runner(self):
        report = assess_messaging_services(
            targets=["vulnerable-mail.corp.internal", "hardened-mail.corp.internal"],
            service_types=["smtp", "rabbitmq"],
            collector=self.collector,
            vantage="internal",
            canary_id="canary_test_id",
        )
        self.assertIsInstance(report, MessagingServicesReport)
        self.assertEqual(report.total_probed, 4)
        self.assertGreater(report.candidates_count, 0)
        self.assertGreater(report.cleanup_receipts_count, 0)

    def test_cli_messaging_discovery_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            targets_file = tmp_path / "mock_targets.json"
            targets_file.write_text(json.dumps(self.mock_services), encoding="utf-8")

            report_file = tmp_path / "report.json"
            cand_file = tmp_path / "candidates.json"
            clean_file = tmp_path / "cleanup.json"

            # 1. Assess
            args_assess = argparse.Namespace(
                messaging_command="assess",
                targets="vulnerable-mail.corp.internal,hardened-mail.corp.internal",
                services="smtp,rabbitmq,kafka",
                vantage="internal",
                scope_ref="test-scope",
                canary_id="canary_run_probe",
                message_budget=5,
                mode="synthetic",
                offline_targets=str(targets_file),
                output=str(report_file),
            )
            ret = command_messaging_discovery(args_assess)
            self.assertEqual(ret, 0)
            self.assertTrue(report_file.is_file())

            # 2. Candidates
            args_cand = argparse.Namespace(
                messaging_command="candidates",
                report=str(report_file),
                output=str(cand_file),
            )
            ret = command_messaging_discovery(args_cand)
            self.assertEqual(ret, 0)
            self.assertTrue(cand_file.is_file())
            candidates = json.loads(cand_file.read_text(encoding="utf-8"))
            self.assertGreater(len(candidates), 0)

            # 3. Cleanup
            args_clean = argparse.Namespace(
                messaging_command="cleanup",
                report=str(report_file),
                output=str(clean_file),
            )
            ret = command_messaging_discovery(args_clean)
            self.assertEqual(ret, 0)
            self.assertTrue(clean_file.is_file())
            receipts = json.loads(clean_file.read_text(encoding="utf-8"))
            self.assertGreater(len(receipts), 0)

            # 4. Inspect
            args_insp = argparse.Namespace(
                messaging_command="inspect",
                report=str(report_file),
                json=True,
            )
            ret = command_messaging_discovery(args_insp)
            self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
