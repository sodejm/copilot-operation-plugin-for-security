"""Collectors and evaluators for mail, chat, and message broker services."""

from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
from typing import Any

from cops.evidence.canonical import canonical, utc_now
from .messaging_models import (
    CleanupReceipt,
    MessagingAuthPrerequisite,
    MessagingCategory,
    MessagingExposureStatus,
    MessagingPrivilegeCandidate,
    MessagingPrivilegeImpact,
    MessagingServiceAssessment,
    MessagingServicesReport,
    MessagingServiceType,
)


DEFAULT_MESSAGING_PORTS: dict[str, tuple[int, str, str]] = {
    # Mail Services
    MessagingServiceType.SMTP.value: (25, "tcp", MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value),
    MessagingServiceType.POP3.value: (110, "tcp", MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value),
    MessagingServiceType.IMAP.value: (143, "tcp", MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value),

    # Real-Time Chat
    MessagingServiceType.IRC.value: (6667, "tcp", MessagingCategory.REALTIME_CHAT.value),

    # Message Brokers & Streaming
    MessagingServiceType.RABBITMQ.value: (5672, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value),
    MessagingServiceType.NATS.value: (4222, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value),
    MessagingServiceType.IBMMQ.value: (1414, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value),
    MessagingServiceType.KAFKA.value: (9092, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value),
    MessagingServiceType.MQTT.value: (1883, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value),
}


class MessagingServicesCollector(ABC):
    """Abstract interface for mail, chat, and message broker service exposure assessment."""

    @abstractmethod
    def resolve_target(self, target_host: str) -> str:
        """Resolve target hostname to IP address string."""

    @abstractmethod
    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        message_budget: int = 5,
        timeout: float = 2.0,
    ) -> MessagingServiceAssessment:
        """Probe and evaluate discrete messaging service exposure."""

    def assess_smtp(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 25) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.SMTP.value, port, "tcp", MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value, vantage, canary_artifact, message_budget, timeout)

    def assess_pop3(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 110) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.POP3.value, port, "tcp", MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value, vantage, canary_artifact, message_budget, timeout)

    def assess_imap(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 143) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.IMAP.value, port, "tcp", MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value, vantage, canary_artifact, message_budget, timeout)

    def assess_irc(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 6667) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.IRC.value, port, "tcp", MessagingCategory.REALTIME_CHAT.value, vantage, canary_artifact, message_budget, timeout)

    def assess_rabbitmq(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 5672) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.RABBITMQ.value, port, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value, vantage, canary_artifact, message_budget, timeout)

    def assess_nats(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 4222) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.NATS.value, port, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value, vantage, canary_artifact, message_budget, timeout)

    def assess_ibmmq(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 1414) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.IBMMQ.value, port, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value, vantage, canary_artifact, message_budget, timeout)

    def assess_kafka(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 9092) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.KAFKA.value, port, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value, vantage, canary_artifact, message_budget, timeout)

    def assess_mqtt(self, target_host: str, canary_artifact: str | None = None, message_budget: int = 5, vantage: str = "external", timeout: float = 2.0, port: int = 1883) -> MessagingServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, MessagingServiceType.MQTT.value, port, "tcp", MessagingCategory.MESSAGE_BROKER_STREAMING.value, vantage, canary_artifact, message_budget, timeout)


class OfflineSyntheticMessagingCollector(MessagingServicesCollector):
    """Deterministic simulation collector for mail, chat, and message broker services."""

    def __init__(self, targets: dict[str, Any] | None = None) -> None:
        self.targets = targets or {}
        self.probes_recorded: list[dict[str, Any]] = []

    def resolve_target(self, target_host: str) -> str:
        try:
            ipaddress.ip_address(target_host)
            return target_host
        except ValueError:
            t_data = self.targets.get(target_host, {})
            return t_data.get("resolved_ip", "198.51.100.160")

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        message_budget: int = 5,
        timeout: float = 2.0,
    ) -> MessagingServiceAssessment:
        self.probes_recorded.append({
            "target_host": target_host,
            "resolved_ip": resolved_ip,
            "service_type": service_type,
            "category": category,
            "port": port,
            "protocol": protocol,
            "vantage": vantage,
            "canary_artifact": canary_artifact,
            "message_budget": message_budget,
        })

        t_data = self.targets.get(target_host) or self.targets.get(resolved_ip) or {}
        svc_data = t_data.get(service_type) or t_data.get(f"{service_type}:{port}")

        # 1. Inaccessible Check (Crucial Truth Boundary: Inaccessible != Secure)
        if (
            svc_data is None
            or t_data.get("unreachable")
            or svc_data.get("inaccessible")
            or svc_data.get("state") in ("filtered", "closed", "timeout")
        ):
            return MessagingServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=MessagingExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=MessagingAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                message_budget_limit=message_budget,
                messages_sent_or_observed=0,
                uncertainty_notes=[
                    "Service was inaccessible from probe vantage; this cannot be reported as secure or hardened"
                ],
                error_message="Probe connection timed out or network route unreachable",
            )

        details = dict(svc_data.get("details", {}))
        for k, v in svc_data.items():
            if k not in (
                "details", "vulnerabilities", "versions", "status", "protected",
                "inaccessible", "remediated", "state", "auth_prerequisite",
                "authentication_required", "role", "role_assigned", "tls_enforced",
                "relay_tested", "relay_permitted", "messages_sent",
            ):
                details.setdefault(k, v)

        # 2. Remediated State Check
        if svc_data.get("remediated"):
            return MessagingServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=MessagingExposureStatus.REMEDIATED.value,
                canary_validated=bool(canary_artifact),
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=svc_data.get("auth_prerequisite", MessagingAuthPrerequisite.USER_PASSWORD.value),
                assigned_role=svc_data.get("role", "authenticated_user"),
                message_budget_limit=message_budget,
                messages_sent_or_observed=min(svc_data.get("messages_sent", 1), message_budget),
                tls_enforced=True,
                relay_tested=True,
                relay_permitted=False,
                applicable_versions=svc_data.get("versions", [details.get("version", "Remediated")]),
                configuration_details=details,
                uncertainty_notes=[
                    "Service verified remediated against historical unauthenticated exposure"
                ],
            )

        # 3. Protected Service Check (Properly authenticated & hardened)
        is_protected = svc_data.get("protected", False)
        auth_req = svc_data.get("authentication_required", True)

        if service_type == MessagingServiceType.SMTP.value and details.get("starttls_enforced") is True and details.get("relay_allowed") is False:
            is_protected = True
        elif service_type == MessagingServiceType.POP3.value and details.get("tls_enforced") is True and details.get("plaintext_auth_allowed") is False:
            is_protected = True
        elif service_type == MessagingServiceType.IMAP.value and details.get("tls_enforced") is True and details.get("anonymous_allowed") is False:
            is_protected = True
        elif service_type == MessagingServiceType.IRC.value and details.get("oper_password_required") is True:
            is_protected = True
        elif service_type == MessagingServiceType.RABBITMQ.value and details.get("guest_enabled") is False and details.get("auth_required") is True:
            is_protected = True
        elif service_type == MessagingServiceType.NATS.value and details.get("auth_required") is True:
            is_protected = True
        elif service_type == MessagingServiceType.IBMMQ.value and details.get("mcauser_enforced") is True and details.get("blank_channel_disabled") is True:
            is_protected = True
        elif service_type == MessagingServiceType.KAFKA.value and details.get("sasl_enabled") is True and details.get("unauthenticated_listeners") is False:
            is_protected = True
        elif service_type == MessagingServiceType.MQTT.value and details.get("allow_anonymous") is False and details.get("auth_required") is True:
            is_protected = True

        canary_active = bool(
            canary_artifact
            or details.get("canary_verified")
            or details.get("canary_message_sent")
        )

        receipts: list[CleanupReceipt] = []
        if canary_active and canary_artifact:
            receipt_id = hashlib.sha256(f"clean:{target_host}:{service_type}:{canary_artifact}".encode("utf-8")).hexdigest()[:16]
            receipts.append(
                CleanupReceipt(
                    receipt_id=f"rec-{receipt_id}",
                    target_host=target_host,
                    service_type=service_type,
                    artifact_type="canary_message",
                    artifact_identifier=canary_artifact,
                    action_taken="verified_removed",
                    verified_clean=True,
                )
            )

        if is_protected:
            default_auth = svc_data.get("auth_prerequisite", MessagingAuthPrerequisite.USER_PASSWORD.value)
            role = svc_data.get("role", "authenticated_user")
            return MessagingServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=MessagingExposureStatus.PROTECTED.value,
                canary_validated=canary_active,
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=default_auth,
                assigned_role=role,
                message_budget_limit=message_budget,
                messages_sent_or_observed=min(svc_data.get("messages_sent", 1), message_budget),
                tls_enforced=svc_data.get("tls_enforced", True),
                relay_tested=bool(svc_data.get("relay_tested", True)),
                relay_permitted=bool(svc_data.get("relay_permitted", False)),
                applicable_versions=svc_data.get("versions", [details.get("version", "Current")]),
                configuration_details=details,
                cleanup_receipts=receipts,
            )

        # 4. Exposed or Misconfigured State
        auth_req = svc_data.get("authentication_required", False)
        auth_prereq = svc_data.get(
            "auth_prerequisite",
            MessagingAuthPrerequisite.NONE.value if not auth_req else MessagingAuthPrerequisite.DEFAULT_CREDENTIALS.value
        )
        assigned_role = svc_data.get("role", "anonymous" if not auth_req else "user")
        status = svc_data.get("status", MessagingExposureStatus.EXPOSED.value)
        applicable_versions = svc_data.get("versions", [details.get("version", "Observed")])
        vulns = list(svc_data.get("vulnerabilities", []))
        candidates: list[MessagingPrivilegeCandidate] = []

        messages_observed = min(svc_data.get("messages_sent", 1), message_budget)
        relay_tested = bool(svc_data.get("relay_tested", service_type == MessagingServiceType.SMTP.value))
        relay_permitted = bool(svc_data.get("relay_permitted", details.get("relay_allowed", False)))

        # Protocol-specific candidate evaluation
        if service_type == MessagingServiceType.SMTP.value:
            if relay_permitted or details.get("relay_allowed") is True:
                vulns.append("SMTP open mail relay permitted; external recipients accepted without authentication")
                c_id = hashlib.sha256(f"smtp_relay:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="smtp_open_relay",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.UNAUTHORIZED_RELAY.value,
                        affected_role="relay_user",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"relay_allowed": True, "tested_recipient": "canary@external-test.example"},
                    )
                )
            if details.get("user_enumeration_enabled") is True or details.get("vrfy_supported") is True:
                vulns.append("SMTP VRFY/EXPN user enumeration supported; unauthenticated recipient verification enabled")
                c_id = hashlib.sha256(f"smtp_enum:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="smtp_user_enumeration",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.CREDENTIAL_HARVESTING.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"command": "VRFY", "response_code": 250},
                    )
                )

        elif service_type == MessagingServiceType.POP3.value:
            if details.get("plaintext_auth_allowed") is True or not details.get("tls_enforced"):
                vulns.append("POP3 server permits plaintext USER/PASS authentication without transport layer security")
                c_id = hashlib.sha256(f"pop3_plain:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="pop3_plaintext_auth",
                        auth_prerequisites=MessagingAuthPrerequisite.USER_PASSWORD.value,
                        privilege_impact=MessagingPrivilegeImpact.CREDENTIAL_HARVESTING.value,
                        affected_role="user",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"plaintext_auth": True, "port": port},
                    )
                )

        elif service_type == MessagingServiceType.IMAP.value:
            if details.get("anonymous_allowed") is True or not auth_req:
                vulns.append("IMAP service accepts anonymous login; unauthenticated mailbox traversal permitted")
                c_id = hashlib.sha256(f"imap_anon:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="imap_anonymous_login",
                        auth_prerequisites=MessagingAuthPrerequisite.ANONYMOUS.value,
                        privilege_impact=MessagingPrivilegeImpact.DATA_EXFILTRATION.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"anonymous_login": True, "folders": details.get("folders", ["INBOX"])},
                    )
                )

        elif service_type == MessagingServiceType.IRC.value:
            if details.get("unauthenticated_oper") is True or details.get("oper_password_required") is False:
                vulns.append("IRC server grants operator status without authentication or uses hardcoded oper credentials")
                c_id = hashlib.sha256(f"irc_oper:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="irc_unauthenticated_operator",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        affected_role="ircop",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"oper_access": True, "server_name": details.get("server_name", "irc.local")},
                    )
                )

        elif service_type == MessagingServiceType.RABBITMQ.value:
            if details.get("guest_enabled") is True:
                vulns.append("RabbitMQ broker retains default guest:guest credentials with administrative privileges")
                c_id = hashlib.sha256(f"rabbit_guest:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="rabbitmq_guest_default_creds",
                        auth_prerequisites=MessagingAuthPrerequisite.DEFAULT_CREDENTIALS.value,
                        privilege_impact=MessagingPrivilegeImpact.BROKER_TAKEOVER.value,
                        affected_role="guest",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"user": "guest", "vhost": "/"},
                    )
                )
            if details.get("open_management") is True:
                vulns.append("RabbitMQ management HTTP API exposed without authentication")
                c_id = hashlib.sha256(f"rabbit_mgmt:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="rabbitmq_open_management",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.BROKER_TAKEOVER.value,
                        affected_role="admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"management_api": True, "version": details.get("version", "3.9.0")},
                    )
                )

        elif service_type == MessagingServiceType.NATS.value:
            if details.get("auth_required") is False or not auth_req:
                vulns.append("NATS streaming broker accepts unauthenticated pub/sub client connections")
                c_id = hashlib.sha256(f"nats_anon:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="nats_unauthenticated_cluster",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.MESSAGE_TAMPERING.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"server_id": details.get("server_id", "nats-node-1"), "cluster": details.get("cluster", "default")},
                    )
                )

        elif service_type == MessagingServiceType.IBMMQ.value:
            if details.get("blank_channel_enabled") is True or details.get("mcauser_enforced") is False:
                vulns.append("IBM MQ SVRCONN channel operates with blank MCAUSER; unauthenticated mqadmin privilege granted")
                c_id = hashlib.sha256(f"ibmmq_mcauser:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="ibmmq_blank_channel",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.BROKER_TAKEOVER.value,
                        affected_role="mqadmin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"channel": details.get("channel", "SYSTEM.DEF.SVRCONN"), "qmgr": details.get("qmgr", "QM1")},
                    )
                )

        elif service_type == MessagingServiceType.KAFKA.value:
            if details.get("sasl_enabled") is False or not auth_req:
                vulns.append("Apache Kafka cluster accepts unauthenticated PLAINTEXT consumer and producer requests")
                c_id = hashlib.sha256(f"kafka_anon:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="kafka_unauthenticated_broker",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.DATA_EXFILTRATION.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"topics": details.get("topics", ["__consumer_offsets", "events"])},
                    )
                )

        elif service_type == MessagingServiceType.MQTT.value:
            if details.get("allow_anonymous") is True or not auth_req:
                vulns.append("MQTT broker accepts anonymous pub/sub connections with wildcards on topic hierarchy")
                c_id = hashlib.sha256(f"mqtt_anon:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    MessagingPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="mqtt_anonymous_read_write",
                        auth_prerequisites=MessagingAuthPrerequisite.NONE.value,
                        privilege_impact=MessagingPrivilegeImpact.MESSAGE_TAMPERING.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"topics_subscribed": details.get("topics", ["#"])},
                    )
                )

        return MessagingServiceAssessment(
            target_host=target_host,
            resolved_ip=resolved_ip,
            service_type=service_type,
            category=category,
            port=port,
            protocol=protocol,
            vantage=vantage,
            exposure_status=status,
            canary_validated=canary_active,
            canary_identifier=canary_artifact,
            authentication_required=auth_req,
            auth_prerequisite=auth_prereq,
            assigned_role=assigned_role,
            message_budget_limit=message_budget,
            messages_sent_or_observed=messages_observed,
            tls_enforced=svc_data.get("tls_enforced", details.get("tls_enforced")),
            relay_tested=relay_tested,
            relay_permitted=relay_permitted,
            applicable_versions=applicable_versions,
            configuration_details=details,
            observed_vulnerabilities=vulns,
            privilege_candidates=candidates,
            cleanup_receipts=receipts,
        )


class StandardSocketMessagingCollector(MessagingServicesCollector):
    """Standard-library socket probe collector for mail, chat, and message broker services."""

    def resolve_target(self, target_host: str) -> str:
        return socket.gethostbyname(target_host)

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = MessagingCategory.MAIL_TRANSFER_RETRIEVAL.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        message_budget: int = 5,
        timeout: float = 2.0,
    ) -> MessagingServiceAssessment:
        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout):
                return MessagingServiceAssessment(
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    service_type=service_type,
                    category=category,
                    port=port,
                    protocol=protocol,
                    vantage=vantage,
                    exposure_status=MessagingExposureStatus.EXPOSED.value,
                    canary_validated=bool(canary_artifact),
                    canary_identifier=canary_artifact,
                    authentication_required=None,
                    auth_prerequisite=MessagingAuthPrerequisite.UNKNOWN.value,
                    assigned_role="unknown",
                    message_budget_limit=message_budget,
                    messages_sent_or_observed=0,
                    configuration_details={"socket_connected": True},
                    uncertainty_notes=["TCP connect succeeded; protocol-level handshake required to verify authentication"],
                )
        except (socket.timeout, ConnectionRefusedError, OSError) as err:
            return MessagingServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=MessagingExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=MessagingAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                message_budget_limit=message_budget,
                messages_sent_or_observed=0,
                error_message=str(err),
                uncertainty_notes=["Service was inaccessible from probe vantage; this cannot be reported as secure"],
            )


def assess_messaging_services(
    targets: list[str],
    service_types: list[str] | None = None,
    collector: MessagingServicesCollector | None = None,
    vantage: str = "external",
    scope_ref: str = "authorized-scope",
    canary_artifact: str | None = None,
    canary_id: str | None = None,
    message_budget: int = 5,
    timeout: float = 2.0,
) -> MessagingServicesReport:
    """Execute exposure and privilege boundary assessment across mail, chat, and broker services."""
    active_collector = collector or StandardSocketMessagingCollector()
    svcs = service_types or list(DEFAULT_MESSAGING_PORTS.keys())
    canary = canary_artifact or canary_id

    report_id = f"msg-rep-{hashlib.sha256(f'{scope_ref}:{vantage}:{','.join(targets)}'.encode('utf-8')).hexdigest()[:16]}"
    assessments: list[MessagingServiceAssessment] = []

    total_exposed = 0
    total_protected = 0
    total_inaccessible = 0
    total_misconfigured = 0
    total_candidates = 0
    total_receipts = 0

    for target in targets:
        resolved_ip = active_collector.resolve_target(target)
        for svc in svcs:
            if svc not in DEFAULT_MESSAGING_PORTS:
                continue
            port, proto, cat = DEFAULT_MESSAGING_PORTS[svc]
            assessment = active_collector.probe_service(
                target_host=target,
                resolved_ip=resolved_ip,
                service_type=svc,
                port=port,
                protocol=proto,
                category=cat,
                vantage=vantage,
                canary_artifact=canary,
                message_budget=message_budget,
                timeout=timeout,
            )
            assessments.append(assessment)

            if assessment.exposure_status == MessagingExposureStatus.EXPOSED.value:
                total_exposed += 1
            elif assessment.exposure_status == MessagingExposureStatus.PROTECTED.value:
                total_protected += 1
            elif assessment.exposure_status == MessagingExposureStatus.INACCESSIBLE.value:
                total_inaccessible += 1
            elif assessment.exposure_status == MessagingExposureStatus.MISCONFIGURED.value:
                total_misconfigured += 1

            total_candidates += len(assessment.privilege_candidates)
            total_receipts += len(assessment.cleanup_receipts)

    return MessagingServicesReport(
        report_id=report_id,
        target_scope=targets,
        vantage=vantage,
        assessments=assessments,
        total_probed=len(assessments),
        total_exposed=total_exposed,
        total_protected=total_protected,
        total_inaccessible=total_inaccessible,
        total_misconfigured=total_misconfigured,
        candidates_count=total_candidates,
        cleanup_receipts_count=total_receipts,
    )
