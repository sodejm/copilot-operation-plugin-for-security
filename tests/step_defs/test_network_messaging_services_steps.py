# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Step definitions for Mail, Messaging, and Message Broker Services BDD scenarios."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    CanaryDeliveryPolicy,
    MessagingAuthPrerequisite,
    MessagingCategory,
    MessagingExposureStatus,
    OfflineSyntheticMessagingCollector,
    assess_messaging_services,
)

scenarios("../../specs/features/network_messaging_services.feature")


@pytest.fixture
def bdd_ctx():
    return {
        "targets": ["vulnerable-msg.corp.internal"],
        "targets_db": {
            "vulnerable-msg.corp.internal": {
                "smtp": {"relay_allowed": True, "user_enumeration_enabled": True, "vrfy_supported": True, "version": "Postfix 3.5"},
                "pop3": {"plaintext_auth_allowed": True, "tls_enforced": False, "version": "Dovecot 2.3"},
                "imap": {"anonymous_allowed": True, "auth_required": False, "tls_enforced": False, "version": "Dovecot 2.3"},
                "irc": {"unauthenticated_oper": True, "oper_password_required": False, "version": "UnrealIRCd 5.0"},
                "rabbitmq": {"guest_enabled": True, "open_management": True, "auth_required": False, "version": "RabbitMQ 3.9"},
                "nats": {"auth_required": False, "version": "NATS 2.8"},
                "ibmmq": {"blank_channel_enabled": True, "mcauser_enforced": False, "version": "IBM MQ 9.2"},
                "kafka": {"sasl_enabled": False, "auth_required": False, "version": "Kafka 3.2"},
                "mqtt": {"allow_anonymous": True, "auth_required": False, "version": "Mosquitto 2.0"},
            },
            "hardened-msg.corp.internal": {
                "smtp": {"protected": True, "starttls_enforced": True, "relay_allowed": False, "auth_required": True, "auth_prerequisite": "user_password", "version": "Postfix 3.7"},
                "rabbitmq": {"protected": True, "guest_enabled": False, "auth_required": True, "auth_prerequisite": "user_password", "version": "RabbitMQ 3.10"},
                "kafka": {"protected": True, "sasl_enabled": True, "unauthenticated_listeners": False, "auth_prerequisite": "sasl", "version": "Kafka 3.4"},
            },
            "filtered-msg.corp.internal": {
                "smtp": {"state": "filtered"},
                "kafka": {"state": "timeout"},
            },
        },
        "collector": None,
        "report": None,
        "assessment": None,
        "candidates": [],
        "budget": 5,
        "canary_id": None,
        "canary_policy": None,
        "canary_mode": None,
    }


# Scenario 1: Assessing mail, chat, and broker services
@given("an approved target host exposing SMTP, POP3, IMAP, IRC, RabbitMQ, NATS, IBM MQ, Kafka, and MQTT")
def setup_multi_protocol_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticMessagingCollector(targets=bdd_ctx["targets_db"])


@when("the messaging services assessment engine executes protocol-specific probes")
def execute_multi_protocol_probes(bdd_ctx):
    bdd_ctx["report"] = assess_messaging_services(
        targets=["vulnerable-msg.corp.internal"],
        collector=bdd_ctx["collector"],
        vantage="internal",
    )


@then("discrete assessments are recorded across mail transfer retrieval, realtime chat, and message broker streaming categories")
def verify_discrete_categories(bdd_ctx):
    report = bdd_ctx["report"]
    categories = {a.category for a in report.assessments}
    assert MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value in categories
    assert MessagingCategory.REALTIME_CHAT.value in categories
    assert MessagingCategory.MESSAGE_BROKER_STREAMING.value in categories


@then("observed configurations, authentication prerequisites, and versions are recorded for each service")
def verify_observed_metadata(bdd_ctx):
    for a in bdd_ctx["report"].assessments:
        assert a.configuration_details is not None
        assert a.auth_prerequisite is not None
        assert a.applicable_versions is not None


# Scenario 2: Enforcing truth boundary
@given("a messaging service that is filtered, connection-refused, or timed out")
def setup_filtered_messaging_service(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticMessagingCollector(targets=bdd_ctx["targets_db"])


@when("the messaging services assessment probe executes")
def execute_filtered_probe(bdd_ctx):
    bdd_ctx["assessment"] = bdd_ctx["collector"].assess_smtp("filtered-msg.corp.internal")


@then('the service exposure status is strictly recorded as "inaccessible"')
def verify_status_inaccessible(bdd_ctx):
    assert bdd_ctx["assessment"].exposure_status == MessagingExposureStatus.INACCESSIBLE.value


@then('the service is never marked as "protected" or "hardened"')
def verify_never_protected(bdd_ctx):
    assert bdd_ctx["assessment"].exposure_status != MessagingExposureStatus.PROTECTED.value


@then('authentication prerequisite is recorded as "unknown" with explicit uncertainty notes')
def verify_uncertainty_notes(bdd_ctx):
    assert bdd_ctx["assessment"].auth_prerequisite == MessagingAuthPrerequisite.UNKNOWN.value
    assert len(bdd_ctx["assessment"].uncertainty_notes) > 0


# Scenario 3: Bounded message budget
@given("an assessment targeting mail and broker services with message budget 5")
def setup_budget_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticMessagingCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["budget"] = 5


@when("messaging service assessment probes execute against candidate brokers")
def execute_budgeted_probes(bdd_ctx):
    bdd_ctx["report"] = assess_messaging_services(
        targets=["vulnerable-msg.corp.internal"],
        service_types=["smtp", "rabbitmq", "kafka"],
        collector=bdd_ctx["collector"],
        message_budget=bdd_ctx["budget"],
    )


@then("each assessment enforces a message budget of 5 messages")
def verify_budget_enforcement(bdd_ctx):
    for a in bdd_ctx["report"].assessments:
        assert a.message_budget_limit == 5
        assert a.messages_sent_or_observed <= 5


@then("no outbound messages are sent by the synthetic or socket collectors")
def verify_zero_mass_relay(bdd_ctx):
    assert all(a.messages_sent_or_observed == 0 for a in bdd_ctx["report"].assessments)


# Scenario 4: Canary validation and cleanup receipts
@given(parsers.parse('an assessment configured with an allowed canary identifier "{canary_id}" and matching delivery and cleanup evidence'))
def setup_canary_id(bdd_ctx, canary_id):
    observed_at = datetime.now(UTC).isoformat()
    bdd_ctx["targets_db"]["vulnerable-msg.corp.internal"]["smtp"]["canary_evidence"] = {
        "identifier": canary_id,
        "recipient": "canary@example.test",
        "destination": "mailbox:canary",
        "delivery_observed": True,
        "messages_sent": 1,
        "cleanup_confirmed": True,
        "delivered_at_utc": observed_at,
        "cleanup_at_utc": observed_at,
    }
    bdd_ctx["collector"] = OfflineSyntheticMessagingCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["canary_id"] = canary_id
    bdd_ctx["canary_policy"] = CanaryDeliveryPolicy(
        destination="mailbox:canary",
        allowed_destinations=("mailbox:canary",),
        recipient="canary@example.test",
        allowed_recipients=("canary@example.test",),
        created_at_utc=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    )


@given("a canary delivery policy with an unauthorized recipient or destination")
def setup_unauthorized_canary(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticMessagingCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["canary_id"] = "canary_mail_probe"
    bdd_ctx["canary_mode"] = "unauthorized"


@given("an expired canary policy or a synthetic fixture exceeding its message budget")
def setup_expired_or_overbudget_canary(bdd_ctx):
    setup_canary_id(bdd_ctx, "canary_mail_probe")
    bdd_ctx["canary_mode"] = "expired_or_overbudget"
    bdd_ctx["targets_db"]["vulnerable-msg.corp.internal"]["smtp"]["canary_evidence"]["messages_sent"] = 2


@when("the messaging services assessment executes canary validation probes")
def execute_canary_probes(bdd_ctx):
    if bdd_ctx["canary_mode"] == "unauthorized":
        for policy in (
            CanaryDeliveryPolicy(
                destination="mailbox:other",
                allowed_destinations=("mailbox:canary",),
                recipient="canary@example.test",
                allowed_recipients=("canary@example.test",),
            ),
            CanaryDeliveryPolicy(
                destination="mailbox:canary",
                allowed_destinations=("mailbox:canary",),
                recipient="other@example.test",
                allowed_recipients=("canary@example.test",),
            ),
        ):
            with pytest.raises(ValueError, match="not explicitly allowed"):
                bdd_ctx["collector"].assess_smtp(
                    "vulnerable-msg.corp.internal",
                    canary_artifact=bdd_ctx["canary_id"],
                    canary_policy=policy,
                )
        return
    if bdd_ctx["canary_mode"] == "expired_or_overbudget":
        expired_policy = CanaryDeliveryPolicy(
            destination="mailbox:canary",
            allowed_destinations=("mailbox:canary",),
            recipient="canary@example.test",
            allowed_recipients=("canary@example.test",),
            created_at_utc=(datetime.now(UTC) - timedelta(hours=2)).isoformat(),
            retention_seconds=3600,
        )
        with pytest.raises(ValueError, match="retention"):
            bdd_ctx["collector"].assess_smtp(
                "vulnerable-msg.corp.internal",
                canary_artifact=bdd_ctx["canary_id"],
                canary_policy=expired_policy,
            )
        bdd_ctx["assessment"] = bdd_ctx["collector"].assess_smtp(
            "vulnerable-msg.corp.internal",
            canary_artifact=bdd_ctx["canary_id"],
            canary_policy=bdd_ctx["canary_policy"],
            message_budget=1,
        )
        return
    bdd_ctx["assessment"] = bdd_ctx["collector"].assess_smtp(
        "vulnerable-msg.corp.internal",
        canary_artifact=bdd_ctx["canary_id"],
        canary_policy=bdd_ctx["canary_policy"],
    )


@then("canary validation status is confirmed in the assessment record")
def verify_canary_confirmed(bdd_ctx):
    assert bdd_ctx["assessment"].canary_validated is True
    assert bdd_ctx["assessment"].canary_identifier == bdd_ctx["canary_id"]


@then(parsers.parse('a synthetic cleanup receipt with "{action_taken}" status and receipt hash is emitted'))
def verify_cleanup_receipt_emitted(bdd_ctx, action_taken):
    receipts = bdd_ctx["assessment"].cleanup_receipts
    assert len(receipts) >= 1
    receipt = receipts[0]
    assert receipt.action_taken == action_taken
    assert receipt.verified_clean is True
    assert receipt.evidence_source == "synthetic_fixture"
    assert len(receipt.receipt_hash) == 64


@then("the canary request is rejected before any probe")
def verify_unauthorized_canary_rejected(bdd_ctx):
    assert bdd_ctx["collector"].probes_recorded == []


@then("no canary is validated and no cleanup receipt is emitted")
def verify_invalid_canary_not_validated(bdd_ctx):
    assert len(bdd_ctx["collector"].probes_recorded) == 1
    assert bdd_ctx["assessment"].canary_validated is False
    assert bdd_ctx["assessment"].cleanup_receipts == []


# Scenario 5: Extracting messaging privilege candidates
@given("an evaluated target exhibiting open relay SMTP, user enumeration, guest RabbitMQ, unauthenticated NATS, and unauthenticated Kafka")
def setup_vulnerable_candidates_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticMessagingCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_messaging_services(
        targets=["vulnerable-msg.corp.internal"],
        service_types=["smtp", "rabbitmq", "nats", "kafka"],
        collector=bdd_ctx["collector"],
    )


@when("messaging privilege candidates are extracted")
def extract_candidates_from_report(bdd_ctx):
    candidates = []
    for a in bdd_ctx["report"].assessments:
        candidates.extend(a.privilege_candidates)
    bdd_ctx["candidates"] = candidates


@then(parsers.parse('actionable candidates for "{c1}", "{c2}", "{c3}", "{c4}", and "{c5}" are generated'))
def verify_expected_candidates(bdd_ctx, c1, c2, c3, c4, c5):
    found_types = {c.finding_type for c in bdd_ctx["candidates"]}
    for expected in (c1, c2, c3, c4, c5):
        assert expected in found_types


@then("each candidate contains service type, target host, port, privilege impact, SHA-256 evidence hash, and remediation guidance")
def verify_candidate_structure(bdd_ctx):
    for c in bdd_ctx["candidates"]:
        assert c.service_type
        assert c.target_host
        assert c.port > 0
        assert c.privilege_impact
        assert len(c.evidence_hash) == 64
        assert len(c.remediation_guidance) > 0


# Scenario 6: Protected and hardened services
@given("a hardened server enforcing SMTP STARTTLS, RabbitMQ auth, and Kafka SASL")
def setup_hardened_server(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticMessagingCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_messaging_services(
        targets=["hardened-msg.corp.internal"],
        service_types=["smtp", "rabbitmq", "kafka"],
        collector=bdd_ctx["collector"],
    )


@when("the messaging services assessment evaluates access controls")
def evaluate_hardened_access_controls(bdd_ctx):
    assert len(bdd_ctx["report"].assessments) == 3


@then('the exposure status is reported as "protected"')
def verify_all_protected(bdd_ctx):
    for a in bdd_ctx["report"].assessments:
        assert a.exposure_status == MessagingExposureStatus.PROTECTED.value


@then('authentication prerequisites reflect "user_password" or "sasl"')
def verify_hardened_prerequisites(bdd_ctx):
    for a in bdd_ctx["report"].assessments:
        assert a.auth_prerequisite in ("user_password", "sasl")


@then("zero unauthenticated messaging privilege candidates are generated")
def verify_zero_candidates(bdd_ctx):
    total_candidates = sum(len(a.privilege_candidates) for a in bdd_ctx["report"].assessments)
    assert total_candidates == 0
