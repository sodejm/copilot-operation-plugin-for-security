# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Unit, contract, and CLI tests for mail, chat, and message broker services assessment."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    CanaryDeliveryPolicy,
    MessagingAuthPrerequisite,
    MessagingCategory,
    MessagingExposureStatus,
    MessagingPrivilegeCandidate,
    MessagingPrivilegeImpact,
    MessagingServiceAssessment,
    MessagingServicesReport,
    MessagingServiceType,
    OfflineSyntheticMessagingCollector,
    StandardSocketMessagingCollector,
    assess_messaging_services,
)
from cops.discovery.cli import (
    command_messaging_discovery,
)
from cops.discovery.messaging_models import CleanupReceipt
from cops.discovery.messaging_collector import MessagingServicesCollector


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

    def test_cleanup_receipt_rejects_changed_contents_and_non_boolean_flags(self):
        receipt = CleanupReceipt(
            receipt_id="rec-msg-002",
            target_host="mail01.corp.internal",
            service_type="smtp",
            artifact_type="canary_message",
            artifact_identifier="canary_mail_probe",
            action_taken="verified_removed",
            verified_clean=True,
        ).to_dict()
        for change in ({"verified_clean": "false"}, {"artifact_identifier": "other"}, {"receipt_hash": "0" * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                CleanupReceipt.from_dict({**receipt, **change})

    def test_verified_synthetic_receipt_rejects_future_time_and_missing_identifier(self):
        observed_at = datetime.now(timezone.utc).isoformat()
        fields = {
            "receipt_id": "rec-synthetic",
            "target_host": "mail01.corp.internal",
            "service_type": "smtp",
            "artifact_type": "canary_message",
            "artifact_identifier": "canary_mail_probe",
            "action_taken": "synthetic_fixture_cleanup_confirmed",
            "verified_clean": True,
            "evidence_source": "synthetic_fixture",
            "timestamp_utc": observed_at,
            "delivered_at_utc": observed_at,
            "retention_started_at_utc": observed_at,
            "retention_seconds": 3600,
        }
        for changes, error in (
            ({"artifact_identifier": None}, "canary identifier"),
            ({"artifact_identifier": "  "}, "canary identifier"),
            ({"timestamp_utc": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}, "future"),
            ({"retention_seconds": None}, "retention"),
            ({"retention_seconds": 86401}, "retention"),
            ({"retention_started_at_utc": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()}, "retention"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, error):
                CleanupReceipt(**{**fields, **changes})

    def test_assessment_rejects_string_boolean_flags(self):
        assessment = MessagingServiceAssessment(
            target_host="mail01.corp.internal",
            resolved_ip="192.0.2.1",
            service_type="smtp",
            category="mail_transfer_retrieval",
            port=25,
        ).to_dict()
        for field_name in ("canary_validated", "relay_tested", "relay_permitted", "tls_enforced"):
            with self.subTest(field=field_name), self.assertRaises(ValueError):
                MessagingServiceAssessment.from_dict({**assessment, field_name: "false"})

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


class TestLegacyCollectorCompatibility(unittest.TestCase):
    def test_collector_without_policy_parameter_keeps_existing_probe_calls(self):
        class LegacyCollector(MessagingServicesCollector):
            def resolve_target(self, target_host):
                return "192.0.2.1"

            def probe_service(
                self, target_host, resolved_ip, service_type, port, protocol="tcp",
                category=MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value,
                vantage="external", canary_artifact=None, message_budget=5, timeout=2.0,
            ):
                return MessagingServiceAssessment(
                    target_host=target_host, resolved_ip=resolved_ip,
                    service_type=service_type, category=category, port=port,
                )

        collector = LegacyCollector()
        for service_type in ("smtp", "pop3", "imap", "irc", "rabbitmq", "nats", "ibmmq", "kafka", "mqtt"):
            with self.subTest(service_type=service_type):
                assessment = getattr(collector, f"assess_{service_type}")("mail.example.test")
                self.assertEqual(assessment.service_type, service_type)
        report = assess_messaging_services(
            ["mail.example.test"], service_types=["smtp"], collector=collector,
        )
        self.assertEqual(len(report.assessments), 1)


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

    @staticmethod
    def canary_policy(**changes):
        fields = {
            "destination": "mailbox:canary",
            "allowed_destinations": ("mailbox:canary",),
            "recipient": "canary@example.test",
            "allowed_recipients": ("canary@example.test",),
            "created_at_utc": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        }
        fields.update(changes)
        return CanaryDeliveryPolicy(**fields)

    def set_canary_evidence(self, identifier="canary_mail_probe", count=2, cleanup=True):
        observed_at = datetime.now(timezone.utc).isoformat()
        self.mock_targets["vulnerable-messaging.corp.internal"]["smtp"]["canary_evidence"] = {
            "identifier": identifier,
            "recipient": "canary@example.test",
            "destination": "mailbox:canary",
            "delivery_observed": True,
            "messages_sent": count,
            "cleanup_confirmed": cleanup,
            "delivered_at_utc": observed_at,
            "cleanup_at_utc": observed_at,
        }

    def test_assess_smtp_open_relay_and_enum(self):
        self.set_canary_evidence()
        policy = self.canary_policy()
        assessment = self.collector.assess_smtp(
            "vulnerable-messaging.corp.internal",
            canary_artifact="canary_mail_probe",
            canary_policy=policy,
        )
        self.assertEqual(assessment.exposure_status, MessagingExposureStatus.EXPOSED.value)
        self.assertTrue(assessment.canary_validated)
        self.assertEqual(assessment.canary_identifier, "canary_mail_probe")
        self.assertTrue(assessment.relay_permitted)
        findings = [c.finding_type for c in assessment.privilege_candidates]
        self.assertIn("smtp_open_relay", findings)
        self.assertIn("smtp_user_enumeration", findings)
        self.assertEqual(len(assessment.cleanup_receipts), 1)
        receipt = assessment.cleanup_receipts[0]
        self.assertEqual(receipt.evidence_source, "synthetic_fixture")
        self.assertEqual(receipt.retention_seconds, 3600)
        self.assertEqual(receipt.retention_started_at_utc, policy.created_at_utc)
        self.assertEqual(CleanupReceipt.from_dict(receipt.to_dict()).receipt_hash, receipt.receipt_hash)
        with self.assertRaisesRegex(ValueError, "hash"):
            CleanupReceipt.from_dict({**receipt.to_dict(), "retention_seconds": 7200})

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

    def test_protected_service_without_canary_evidence(self):
        smtp_res = self.collector.assess_smtp(
            "hardened-messaging.corp.internal",
            canary_artifact="canary_probe",
            canary_policy=self.canary_policy(),
        )
        self.assertEqual(smtp_res.exposure_status, MessagingExposureStatus.PROTECTED.value)
        self.assertTrue(smtp_res.tls_enforced)
        self.assertFalse(smtp_res.relay_permitted)
        self.assertEqual(len(smtp_res.privilege_candidates), 0)
        self.assertFalse(smtp_res.canary_validated)
        self.assertEqual(len(smtp_res.cleanup_receipts), 0)

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
        self.set_canary_evidence(count=2)
        res = self.collector.assess_smtp(
            "vulnerable-messaging.corp.internal",
            canary_artifact="canary_mail_probe",
            canary_policy=self.canary_policy(),
            message_budget=1,
        )
        self.assertEqual(res.message_budget_limit, 1)
        self.assertEqual(res.messages_sent_or_observed, 2)
        self.assertFalse(res.canary_validated)
        self.assertEqual(res.cleanup_receipts, [])
        self.assertTrue(any("more messages" in note for note in res.uncertainty_notes))

    def test_canary_policy_rejects_unauthorized_route_before_probe(self):
        for changes in (
            {"destination": "topic:outside"},
            {"recipient": "outside@example.test"},
        ):
            with self.subTest(changes=changes), patch.object(self.collector, "resolve_target") as resolve:
                with self.assertRaisesRegex(ValueError, "not explicitly allowed"):
                    self.collector.assess_smtp(
                        "vulnerable-messaging.corp.internal",
                        canary_artifact="canary_mail_probe",
                        canary_policy=self.canary_policy(**changes),
                    )
                resolve.assert_not_called()
        self.assertEqual(self.collector.probes_recorded, [])

    def test_canary_policy_rejects_string_and_malformed_allowlists_before_probe(self):
        for changes in (
            {"destination": "canary", "allowed_destinations": "mailbox:canary"},
            {"recipient": "canary", "allowed_recipients": "canary@example.test"},
            {"allowed_destinations": ("mailbox:canary", "")},
            {"allowed_recipients": ("canary@example.test", None)},
        ):
            with self.subTest(changes=changes), patch.object(self.collector, "resolve_target") as resolve:
                with self.assertRaises(ValueError):
                    self.collector.assess_smtp(
                        "vulnerable-messaging.corp.internal",
                        canary_artifact="canary_mail_probe",
                        canary_policy=self.canary_policy(**changes),
                    )
                resolve.assert_not_called()
        self.assertEqual(self.collector.probes_recorded, [])

    def test_canary_policy_rejects_expired_or_unbounded_retention(self):
        expired = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        for changes in (
            {"created_at_utc": expired},
            {"retention_seconds": 0},
            {"retention_seconds": 86401},
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, "retention"):
                    self.collector.assess_smtp(
                        "vulnerable-messaging.corp.internal",
                        canary_artifact="canary_mail_probe",
                        canary_policy=self.canary_policy(**changes),
                    )
        self.assertEqual(self.collector.probes_recorded, [])

    def test_canary_requires_policy_and_positive_bounded_budget(self):
        for policy, budget in ((None, 5), (self.canary_policy(), 0), (self.canary_policy(), 6)):
            with self.subTest(policy=policy, budget=budget):
                with self.assertRaises(ValueError):
                    self.collector.assess_smtp(
                        "vulnerable-messaging.corp.internal",
                        canary_artifact="canary_mail_probe",
                        canary_policy=policy,
                        message_budget=budget,
                    )
        self.assertEqual(self.collector.probes_recorded, [])

    def test_delivery_without_cleanup_confirmation_has_no_receipt(self):
        self.set_canary_evidence(cleanup=False)
        res = self.collector.assess_smtp(
            "vulnerable-messaging.corp.internal",
            canary_artifact="canary_mail_probe",
            canary_policy=self.canary_policy(),
        )
        self.assertTrue(res.canary_validated)
        self.assertEqual(res.cleanup_receipts, [])
        self.assertTrue(any("cleanup" in note for note in res.uncertainty_notes))

    def test_delivery_timestamp_must_be_in_authorized_window(self):
        self.set_canary_evidence()
        evidence = self.mock_targets["vulnerable-messaging.corp.internal"]["smtp"]["canary_evidence"]
        for delivered_at in (
            (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
            (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            datetime.now().isoformat(),
        ):
            with self.subTest(delivered_at=delivered_at):
                evidence["delivered_at_utc"] = delivered_at
                result = self.collector.assess_smtp(
                    "vulnerable-messaging.corp.internal",
                    canary_artifact="canary_mail_probe",
                    canary_policy=self.canary_policy(),
                )
                self.assertFalse(result.canary_validated)
                self.assertEqual(result.cleanup_receipts, [])

    def test_cleanup_timestamp_must_follow_delivery_within_retention(self):
        self.set_canary_evidence()
        evidence = self.mock_targets["vulnerable-messaging.corp.internal"]["smtp"]["canary_evidence"]
        delivered_at = evidence["delivered_at_utc"]
        for cleanup_at in (
            (datetime.fromisoformat(delivered_at) - timedelta(seconds=1)).isoformat(),
            (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            datetime.now().isoformat(),
        ):
            with self.subTest(cleanup_at=cleanup_at):
                evidence["cleanup_at_utc"] = cleanup_at
                result = self.collector.assess_smtp(
                    "vulnerable-messaging.corp.internal",
                    canary_artifact="canary_mail_probe",
                    canary_policy=self.canary_policy(),
                )
                self.assertTrue(result.canary_validated)
                self.assertEqual(result.cleanup_receipts, [])

    def test_broker_canary_policy_does_not_require_mail_recipient(self):
        broker = self.mock_targets["vulnerable-messaging.corp.internal"]["kafka"]
        observed_at = datetime.now(timezone.utc).isoformat()
        broker["canary_evidence"] = {
            "identifier": "topic_probe",
            "destination": "topic:canary",
            "delivery_observed": True,
            "messages_sent": 1,
            "cleanup_confirmed": True,
            "delivered_at_utc": observed_at,
            "cleanup_at_utc": observed_at,
        }
        result = self.collector.assess_kafka(
            "vulnerable-messaging.corp.internal",
            canary_artifact="topic_probe",
            canary_policy=self.canary_policy(
                destination="topic:canary", allowed_destinations=("topic:canary",),
                recipient=None, allowed_recipients=(),
            ),
        )
        self.assertTrue(result.canary_validated)
        self.assertEqual(len(result.cleanup_receipts), 1)

    def test_assess_messaging_services_runner_counts(self):
        self.set_canary_evidence(identifier="canary_batch")
        report = assess_messaging_services(
            targets=["vulnerable-messaging.corp.internal", "hardened-messaging.corp.internal", "unreachable.corp.internal"],
            service_types=["smtp", "kafka"],
            collector=self.collector,
            vantage="external",
            canary_id="canary_batch",
            canary_policy=self.canary_policy(),
        )
        self.assertEqual(report.total_probed, 6)
        self.assertGreater(report.total_exposed, 0)
        self.assertGreater(report.total_protected, 0)
        self.assertGreater(report.total_inaccessible, 0)
        self.assertGreater(report.candidates_count, 0)
        self.assertGreater(report.cleanup_receipts_count, 0)

    def test_socket_collector_does_not_send_or_claim_canary_delivery(self):
        collector = StandardSocketMessagingCollector()
        connection = MagicMock()
        connection.__enter__.return_value = connection
        with patch("cops.discovery.messaging_collector.socket.create_connection", return_value=connection):
            result = collector.probe_service(
                "mail.example.test", "192.0.2.10", "smtp", 25,
                canary_artifact="canary_mail_probe", canary_policy=self.canary_policy(),
            )
        connection.send.assert_not_called()
        connection.sendall.assert_not_called()
        self.assertFalse(result.canary_validated)
        self.assertEqual(result.messages_sent_or_observed, 0)
        self.assertEqual(result.cleanup_receipts, [])


class TestMessagingServicesCLI(unittest.TestCase):
    def setUp(self):
        observed_at = datetime.now(timezone.utc).isoformat()
        self.mock_targets = {
            "mail01.corp.internal": {
                "smtp": {
                    "relay_allowed": True,
                    "version": "Postfix 3.5",
                    "canary_evidence": {
                        "identifier": "canary_cli_probe",
                        "recipient": "canary@example.test",
                        "destination": "mailbox:canary",
                        "delivery_observed": True,
                        "messages_sent": 1,
                        "cleanup_confirmed": True,
                        "delivered_at_utc": observed_at,
                        "cleanup_at_utc": observed_at,
                    },
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
                canary_destination="mailbox:canary",
                allow_canary_destination=["mailbox:canary"],
                canary_recipient="canary@example.test",
                allow_canary_recipient=["canary@example.test"],
                canary_created_at_utc=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                canary_retention_seconds=3600,
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

    def test_cleanup_export_rejects_malformed_report_evidence(self):
        delivered_at = datetime.now(timezone.utc).isoformat()
        receipt = CleanupReceipt(
            receipt_id="rec-cli",
            target_host="mail01.corp.internal",
            service_type="smtp",
            artifact_type="canary_message",
            artifact_identifier="canary_cli_probe",
            action_taken="synthetic_fixture_cleanup_confirmed",
            verified_clean=True,
            evidence_source="synthetic_fixture",
            timestamp_utc=delivered_at,
            delivered_at_utc=delivered_at,
            retention_started_at_utc=delivered_at,
            retention_seconds=3600,
        )
        assessment = MessagingServiceAssessment(
            target_host="mail01.corp.internal",
            resolved_ip="192.0.2.1",
            service_type="smtp",
            category="mail_transfer_retrieval",
            port=25,
            canary_validated=True,
            canary_identifier="canary_cli_probe",
            messages_sent_or_observed=1,
            cleanup_receipts=[receipt],
        )
        report = MessagingServicesReport(
            report_id="report-cli",
            target_scope=["mail01.corp.internal"],
            assessments=[assessment],
        ).to_dict()
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            output_path = Path(tmpdir) / "receipts.json"
            args = argparse.Namespace(messaging_command="cleanup", report=str(report_path), output=str(output_path))
            report_path.write_text(json.dumps(report), encoding="utf-8")
            self.assertEqual(command_messaging_discovery(args), 0)
            self.assertEqual(len(json.loads(output_path.read_text(encoding="utf-8"))), 1)
            output_path.unlink()
            assessment_data = report["assessments"][0]

            def changed_receipt(**changes):
                updated = {**receipt.to_dict(), **changes}
                updated.pop("receipt_hash")
                canonical = json.dumps(updated, sort_keys=True, separators=(",", ":")).encode()
                updated["receipt_hash"] = hashlib.sha256(canonical).hexdigest()
                return updated

            future_time = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
            stale_delivery = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
            stale_cleanup = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            for malformed in (
                {**report, "assessments": [{**report["assessments"][0], "canary_validated": "false"}]},
                {**report, "assessments": [{**report["assessments"][0], "cleanup_receipts": [{**receipt.to_dict(), "receipt_hash": "0" * 64}]}]},
                {**report, "assessments": [{**assessment_data, "canary_identifier": None, "cleanup_receipts": [changed_receipt(artifact_identifier=None)]}]},
                {**report, "assessments": [{**assessment_data, "cleanup_receipts": [changed_receipt(timestamp_utc=future_time, delivered_at_utc=future_time)]}]},
                {**report, "assessments": [{**assessment_data, "cleanup_receipts": [changed_receipt(
                    timestamp_utc=stale_cleanup,
                    delivered_at_utc=stale_delivery,
                    retention_started_at_utc=stale_delivery,
                    retention_seconds=86400,
                )]}]},
                *(
                    {**report, "assessments": [{**assessment_data, field: value}]}
                    for field, value in (
                        ("canary_identifier", ""),
                        ("canary_identifier", "  "),
                        ("message_budget_limit", 0),
                        ("message_budget_limit", 6),
                        ("message_budget_limit", False),
                        ("messages_sent_or_observed", 0),
                        ("messages_sent_or_observed", -1),
                        ("messages_sent_or_observed", 6),
                        ("messages_sent_or_observed", "1"),
                        ("messages_sent_or_observed", True),
                    )
                ),
                [],
            ):
                with self.subTest(malformed=malformed):
                    report_path.write_text(json.dumps(malformed), encoding="utf-8")
                    self.assertEqual(command_messaging_discovery(args), 2)
                    self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
