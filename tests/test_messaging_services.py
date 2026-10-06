# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Unit, contract, and CLI tests for mail, chat, and message broker services assessment."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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
from cops.discovery.cli import (
    command_messaging_discovery,
)


class TestMessagingModelsAndSerialization(unittest.TestCase):
    def test_messaging_privilege_candidate_post_init_and_serialization(self):
        cand = MessagingPrivilegeCandidate(
            candidate_id="cand-smtp-01",
            service_type="smtp",
            category="mail_transfer_retrieval",
            target_host="mail01.corp.internal",
            port=25,
            vantage="external",
            finding_type="smtp_open_relay",
            auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
            privilege_impact=MessagingPrivilegeImpact.UNAUTHORIZED_RELAY.value,
        )
        self.assertTrue(cand.evidence_hash)
        self.assertIn("open relaying", cand.remediation_guidance)
        d = cand.to_dict()
        reconstructed = MessagingPrivilegeCandidate.from_dict(d)
        self.assertEqual(reconstructed.candidate_id, cand.candidate_id)
        self.assertEqual(reconstructed.evidence_hash, cand.evidence_hash)
        self.assertEqual(reconstructed.remediation_guidance, cand.remediation_guidance)
        self.assertEqual(reconstructed.privilege_impact, MessagingPrivilegeImpact.UNAUTHORIZED_RELAY.value)

    def test_cleanup_receipt_post_init_and_serialization(self):
        receipt = CleanupReceipt(
            receipt_id="rec-msg-001",
            target_host="mail01.corp.internal",
            service_type="smtp",
            artifact_type="canary_mail",
            artifact_identifier="canary_mail_probe",
            action_taken="verified_removed",
            verified_clean=True,
        )
        self.assertTrue(receipt.receipt_hash)
        d = receipt.to_dict()
        reconstructed = CleanupReceipt.from_dict(d)
        self.assertEqual(reconstructed.receipt_id, receipt.receipt_id)
        self.assertEqual(reconstructed.receipt_hash, receipt.receipt_hash)
        self.assertTrue(reconstructed.verified_clean)

    def test_messaging_service_assessment_serialization_roundtrip(self):
        cand = MessagingPrivilegeCandidate(
            candidate_id="cand-rabbit-01",
            service_type="rabbitmq",
            category="message_broker_streaming",
            target_host="broker01.corp.internal",
            port=5672,
            vantage="internal",
            finding_type="rabbitmq_guest_default_creds",
            auth_prerequisites=MessagingAuthPrerequisite.DEFAULT_CREDENTIALS.value,
            privilege_impact=MessagingPrivilegeImpact.BROKER_TAKEOVER.value,
        )
        receipt = CleanupReceipt(
            receipt_id="rec-rabbit-002",
            target_host="broker01.corp.internal",
            service_type="rabbitmq",
            artifact_type="canary_queue",
            artifact_identifier="canary_queue_probe",
            action_taken="verified_removed",
            verified_clean=True,
        )
        assessment = MessagingServiceAssessment(
            target_host="broker01.corp.internal",
            resolved_ip="198.51.100.45",
            service_type=MessagingServiceType.RABBITMQ.value,
            category=MessagingCategory.MESSAGE_BROKER_STREAMING.value,
            port=5672,
            protocol="tcp",
            vantage="internal",
            exposure_status=MessagingExposureStatus.EXPOSED.value,
            canary_validated=True,
            canary_identifier="canary_queue_probe",
            authentication_required=True,
            auth_prerequisite=MessagingAuthPrerequisite.DEFAULT_CREDENTIALS.value,
            assigned_role="guest",
            message_budget_limit=5,
            messages_sent_or_observed=1,
            applicable_versions=["3.9.0"],
            configuration_details={"guest_enabled": True},
            observed_vulnerabilities=["Default guest credentials enabled"],
            privilege_candidates=[cand],
            cleanup_receipts=[receipt],
        )

        d = assessment.to_dict()
        reconstructed = MessagingServiceAssessment.from_dict(d)
        self.assertEqual(reconstructed.target_host, "broker01.corp.internal")
        self.assertEqual(reconstructed.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertEqual(reconstructed.message_budget_limit, 5)
        self.assertEqual(len(reconstructed.privilege_candidates), 1)
        self.assertEqual(len(reconstructed.cleanup_receipts), 1)

    def test_messaging_services_report_save_and_load(self):
        report = MessagingServicesReport(
            report_id="test-msg-report-01",
            target_scope=["mail01.corp.internal"],
            vantage="external",
            assessments=[],
            total_probed=0,
            total_exposed=0,
            total_protected=0,
            total_inaccessible=0,
            total_misconfigured=0,
            candidates_count=0,
            cleanup_receipts_count=0,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "msg_report.json"
            report.save(file_path)
            self.assertTrue(file_path.is_file())

            loaded = MessagingServicesReport.load(file_path)
            self.assertEqual(loaded.report_id, report.report_id)
            self.assertEqual(loaded.target_scope, report.target_scope)


class TestOfflineSyntheticMessagingCollector(unittest.TestCase):
    def setUp(self):
        self.mock_targets = {
            "vulnerable-messaging.corp.internal": {
                "smtp": {
                    "relay_allowed": True,
                    "user_enumeration_enabled": True,
                    "vrfy_supported": True,
                    "messages_sent": 2,
                    "version": "Exim 4.94",
                },
                "pop3": {
                    "plaintext_auth_allowed": True,
                    "tls_enforced": False,
                    "version": "Courier 1.0",
                },
                "imap": {
                    "anonymous_allowed": True,
                    "auth_required": False,
                    "tls_enforced": False,
                    "version": "Courier 1.0",
                },
                "irc": {
                    "unauthenticated_oper": True,
                    "oper_password_required": False,
                    "version": "UnrealIRCd 5.0",
                },
                "rabbitmq": {
                    "guest_enabled": True,
                    "open_management": True,
                    "auth_required": False,
                    "version": "RabbitMQ 3.8.0",
                },
                "nats": {
                    "auth_required": False,
                    "version": "NATS 2.6.0",
                },
                "ibmmq": {
                    "blank_channel_enabled": True,
                    "mcauser_enforced": False,
                    "version": "IBM MQ 9.1",
                },
                "kafka": {
                    "sasl_enabled": False,
                    "auth_required": False,
                    "version": "Kafka 2.8.0",
                },
                "mqtt": {
                    "allow_anonymous": True,
                    "auth_required": False,
                    "version": "Mosquitto 1.6.9",
                },
            },
            "hardened-messaging.corp.internal": {
                "smtp": {
                    "protected": True,
                    "starttls_enforced": True,
                    "relay_allowed": False,
                    "authentication_required": True,
                    "auth_prerequisite": MessagingAuthPrerequisite.USER_PASSWORD.value,
                    "version": "Postfix 3.7",
                },
                "kafka": {
                    "protected": True,
                    "sasl_enabled": True,
                    "unauthenticated_listeners": False,
                    "auth_prerequisite": MessagingAuthPrerequisite.SASL.value,
                    "version": "Kafka 3.3.1",
                },
            },
            "remediated-mail.corp.internal": {
                "smtp": {
                    "remediated": True,
                    "auth_prerequisite": MessagingAuthPrerequisite.USER_PASSWORD.value,
                    "version": "Postfix 3.7-remediated",
                }
            },
            "unreachable.corp.internal": {
                "unreachable": True,
            },
        }
        self.collector = OfflineSyntheticMessagingCollector(targets=self.mock_targets)

    def test_assess_smtp_open_relay_and_enum(self):
        assessment = self.collector.assess_smtp("vulnerable-messaging.corp.internal", canary_artifact="canary_mail_probe")
        self.assertEqual(assessment.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(assessment.canary_validated)
        self.assertEqual(assessment.canary_identifier, "canary_mail_probe")
        self.assertTrue(assessment.relay_permitted)
        findings = [c.finding_type for c in assessment.privilege_candidates]
        self.assertIn("smtp_open_relay", findings)
        self.assertIn("smtp_user_enumeration", findings)
        self.assertEqual(len(assessment.cleanup_receipts), 1)

    def test_assess_pop3_and_imap(self):
        pop3_res = self.collector.assess_pop3("vulnerable-messaging.corp.internal")
        self.assertEqual(pop3_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "pop3_plaintext_auth" for c in pop3_res.privilege_candidates))

        imap_res = self.collector.assess_imap("vulnerable-messaging.corp.internal")
        self.assertEqual(imap_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "imap_anonymous_login" for c in imap_res.privilege_candidates))

    def test_assess_irc(self):
        irc_res = self.collector.assess_irc("vulnerable-messaging.corp.internal")
        self.assertEqual(irc_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(any(c.finding_type == "irc_unauthenticated_operator" for c in irc_res.privilege_candidates))

    def test_assess_all_brokers(self):
        rabbit_res = self.collector.assess_rabbitmq("vulnerable-messaging.corp.internal")
        self.assertEqual(rabbit_res.exposure_status, MessagingExposureStatus.EXPOSED.value)
        rabbit_findings = [c.finding_type for c in rabbit_res.privilege_candidates]
        self.assertIn("rabbitmq_guest_default_creds", rabbit_findings)
        self.assertIn("rabbitmq_open_management", rabbit_findings)

        nats_res = self.collector.assess_nats("vulnerable-messaging.corp.internal")
        self.assertTrue(any(c.finding_type == "nats_unauthenticated_cluster" for c in nats_res.privilege_candidates))

        ibmmq_res = self.collector.assess_ibmmq("vulnerable-messaging.corp.internal")
        self.assertTrue(any(c.finding_type == "ibmmq_blank_channel" for c in ibmmq_res.privilege_candidates))

        kafka_res = self.collector.assess_kafka("vulnerable-messaging.corp.internal")
        self.assertTrue(any(c.finding_type == "kafka_unauthenticated_broker" for c in kafka_res.privilege_candidates))

        mqtt_res = self.collector.assess_mqtt("vulnerable-messaging.corp.internal")
        self.assertTrue(any(c.finding_type == "mqtt_anonymous_read_write" for c in mqtt_res.privilege_candidates))

    def test_protected_service_and_receipt(self):
        smtp_res = self.collector.assess_smtp("hardened-messaging.corp.internal", canary_artifact="canary_probe")
        self.assertEqual(smtp_res.exposure_status, MessagingExposureStatus.PROTECTED.value)
        self.assertTrue(smtp_res.tls_enforced)
        self.assertFalse(smtp_res.relay_permitted)
        self.assertEqual(len(smtp_res.privilege_candidates), 0)
        self.assertEqual(len(smtp_res.cleanup_receipts), 1)

        kafka_res = self.collector.assess_kafka("hardened-messaging.corp.internal")
        self.assertEqual(kafka_res.exposure_status, MessagingExposureStatus.PROTECTED.value)
        self.assertEqual(len(kafka_res.privilege_candidates), 0)

    def test_remediated_service(self):
        res = self.collector.assess_smtp("remediated-mail.corp.internal")
        self.assertEqual(res.exposure_status, MessagingExposureStatus.REMEDIATED.value)
        self.assertEqual(res.auth_prerequisite, MessagingAuthPrerequisite.USER_PASSWORD.value)

    def test_inaccessible_truth_boundary(self):
        res = self.collector.assess_smtp("unreachable.corp.internal")
        self.assertEqual(res.exposure_status, MessagingExposureStatus.INACCESSIBLE.value)
        self.assertEqual(res.auth_prerequisite, MessagingAuthPrerequisite.UNKNOWN.value)
        self.assertFalse(res.canary_validated)
        self.assertIn("Service was inaccessible from probe vantage; this cannot be reported as secure or hardened", res.uncertainty_notes[0])

    def test_message_budget_enforcement(self):
        res = self.collector.assess_smtp("vulnerable-messaging.corp.internal", message_budget=1)
        self.assertEqual(res.message_budget_limit, 1)
        self.assertEqual(res.messages_sent_or_observed, 1)

    def test_assess_messaging_services_runner_counts(self):
        report = assess_messaging_services(
            targets=["vulnerable-messaging.corp.internal", "hardened-messaging.corp.internal", "unreachable.corp.internal"],
            service_types=["smtp", "kafka"],
            collector=self.collector,
            vantage="external",
            canary_id="canary_batch",
        )
        self.assertEqual(report.total_probed, 6)
        self.assertGreater(report.total_exposed, 0)
        self.assertGreater(report.total_protected, 0)
        self.assertGreater(report.total_inaccessible, 0)
        self.assertGreater(report.candidates_count, 0)
        self.assertGreater(report.cleanup_receipts_count, 0)


class TestMessagingServicesCLI(unittest.TestCase):
    def setUp(self):
        self.mock_targets = {
            "mail01.corp.internal": {
                "smtp": {
                    "relay_allowed": True,
                    "version": "Postfix 3.5",
                },
                "rabbitmq": {
                    "guest_enabled": True,
                    "version": "3.8.14",
                },
            }
        }

    def test_cli_lifecycle_commands(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            targets_file = tmp_path / "targets.json"
            targets_file.write_text(json.dumps(self.mock_targets), encoding="utf-8")

            report_file = tmp_path / "report.json"
            cand_file = tmp_path / "cand.json"
            clean_file = tmp_path / "clean.json"

            # 1. Assess
            args_assess = argparse.Namespace(
                messaging_command="assess",
                targets="mail01.corp.internal",
                services="smtp,rabbitmq",
                vantage="internal",
                scope_ref="test-scope",
                canary_id="canary_cli_probe",
                message_budget=5,
                mode="synthetic",
                offline_targets=str(targets_file),
                output=str(report_file),
            )
            self.assertEqual(command_messaging_discovery(args_assess), 0)
            self.assertTrue(report_file.is_file())

            # 2. Candidates
            args_cand = argparse.Namespace(
                messaging_command="candidates",
                report=str(report_file),
                output=str(cand_file),
            )
            self.assertEqual(command_messaging_discovery(args_cand), 0)
            self.assertTrue(cand_file.is_file())
            candidates = json.loads(cand_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(candidates), 2)

            # 3. Cleanup
            args_clean = argparse.Namespace(
                messaging_command="cleanup",
                report=str(report_file),
                output=str(clean_file),
            )
            self.assertEqual(command_messaging_discovery(args_clean), 0)
            self.assertTrue(clean_file.is_file())
            receipts = json.loads(clean_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(receipts), 1)

            # 4. Inspect
            args_insp_json = argparse.Namespace(
                messaging_command="inspect",
                report=str(report_file),
                json=True,
            )
            self.assertEqual(command_messaging_discovery(args_insp_json), 0)

            args_insp_text = argparse.Namespace(
                messaging_command="inspect",
                report=str(report_file),
                json=False,
            )
            self.assertEqual(command_messaging_discovery(args_insp_text), 0)


if __name__ == "__main__":
    unittest.main()
