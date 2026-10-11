"""Data models and taxonomy for mail, messaging, and message broker services."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cops.evidence.canonical import utc_now

from .models import EvidenceProvenance


def _literal_bool(value: Any, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field_name} must be a JSON boolean")
    return value


def _literal_int(value: Any, field_name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{field_name} must be a JSON integer")
    return value


def _optional_literal_bool(value: Any, field_name: str) -> bool | None:
    return None if value is None else _literal_bool(value, field_name)


def _aware_timestamp(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a timezone-aware timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware timestamp")
    return parsed


class MessagingCategory(str, Enum):
    """Broad category taxonomy for mail, chat, and message broker services."""

    MAIL_TRANSFER_RETRIEVAL = "mail_transfer_retrieval"
    REALTIME_CHAT = "realtime_chat"
    MESSAGE_BROKER_STREAMING = "message_broker_streaming"


class MessagingServiceType(str, Enum):
    """Specific protocol and broker taxonomy for mail, chat, and streaming engines."""

    # Mail Services
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"

    # Real-Time Chat
    IRC = "irc"

    # Message Brokers & Queues
    RABBITMQ = "rabbitmq"
    NATS = "nats"
    IBMMQ = "ibmmq"
    KAFKA = "kafka"
    MQTT = "mqtt"


class MessagingExposureStatus(str, Enum):
    """Reachability and exposure posture for mail, chat, and message broker services."""

    EXPOSED = "exposed"
    PROTECTED = "protected"
    INACCESSIBLE = "inaccessible"
    MISCONFIGURED = "misconfigured"
    REMEDIATED = "remediated"


class MessagingAuthPrerequisite(str, Enum):
    """Authentication and boundary prerequisite required to interact with messaging service."""

    NONE = "none"
    ANONYMOUS = "anonymous"
    DEFAULT_CREDENTIALS = "default_credentials"
    USER_PASSWORD = "user_password"  # noqa: S105 - schema label or operation identifier, not a credential
    CLIENT_CERT = "client_cert"
    TOKEN_OR_API_KEY = "token_or_api_key"  # noqa: S105 - schema label or operation identifier, not a credential
    SASL = "sasl"
    UNKNOWN = "unknown"


class MessagingPrivilegeImpact(str, Enum):
    """Security and operational impact of an exposed or misconfigured messaging service."""

    REMOTE_CODE_EXECUTION = "remote_code_execution"
    BROKER_TAKEOVER = "broker_takeover"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    DATA_EXFILTRATION = "data_exfiltration"
    MESSAGE_TAMPERING = "message_tampering"
    UNAUTHORIZED_RELAY = "unauthorized_relay"
    NONE = "none"


@dataclass(frozen=True)
class CanaryDeliveryPolicy:
    """Explicit route and lifetime for a synthetic messaging canary."""

    destination: str
    allowed_destinations: tuple[str, ...]
    recipient: str | None = None
    allowed_recipients: tuple[str, ...] = ()
    created_at_utc: str = field(default_factory=utc_now)
    retention_seconds: int = 3600

    def validate(self, service_type: str, now: datetime | None = None) -> None:
        if (
            not isinstance(self.allowed_destinations, (list, tuple))
            or not self.allowed_destinations
            or any(not isinstance(item, str) or not item.strip() for item in self.allowed_destinations)
        ):
            raise ValueError("Canary destinations must be an explicit list of nonempty strings")
        if (
            not isinstance(self.allowed_recipients, (list, tuple))
            or any(not isinstance(item, str) or not item.strip() for item in self.allowed_recipients)
        ):
            raise ValueError("Canary recipients must be an explicit list of nonempty strings")
        if not isinstance(self.destination, str) or not self.destination.strip() or self.destination not in self.allowed_destinations:
            raise ValueError("Canary destination is not explicitly allowed")
        if service_type in {"smtp", "pop3", "imap"} and not self.recipient:
            raise ValueError("Mail canary requires an explicit recipient")
        if self.recipient is not None and (
            not isinstance(self.recipient, str)
            or not self.recipient.strip()
            or self.recipient not in self.allowed_recipients
        ):
            raise ValueError("Canary recipient is not explicitly allowed")
        if type(self.retention_seconds) is not int or not 0 < self.retention_seconds <= 86400:
            raise ValueError("Canary retention must be between 1 and 86400 seconds")
        try:
            created = datetime.fromisoformat(self.created_at_utc.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("Canary creation time is invalid") from exc
        if created.tzinfo is None:
            raise ValueError("Canary creation time must include a timezone")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("Current time must include a timezone")
        if created > current or current >= created + timedelta(seconds=self.retention_seconds):
            raise ValueError("Canary retention window is not active")


@dataclass
class MessagingPrivilegeCandidate:
    """Actionable finding for unauthorized relay, broker takeover, or message interception."""

    candidate_id: str
    service_type: str
    category: str
    target_host: str
    port: int
    vantage: str = "external"
    finding_type: str = "unauthenticated_messaging"
    auth_prerequisites: str = MessagingAuthPrerequisite.NONE.value
    privilege_impact: str = MessagingPrivilegeImpact.MESSAGE_TAMPERING.value
    affected_role: str = "anonymous"
    applicable_versions: list[str] = field(default_factory=list)
    supporting_evidence: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str = ""
    remediation_guidance: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_hash:
            canonical_blob = f"{self.service_type}:{self.target_host}:{self.port}:{self.finding_type}:{self.auth_prerequisites}:{self.privilege_impact}".encode()
            self.evidence_hash = hashlib.sha256(canonical_blob).hexdigest()
        if not self.remediation_guidance:
            self.remediation_guidance = self._default_remediation()

    def _default_remediation(self) -> str:
        guidance_map = {
            "smtp_open_relay": "Disable open relaying in mail transport agent; restrict relay access strictly to authenticated users or trusted internal networks.",
            "smtp_user_enumeration": "Disable VRFY and EXPN commands; configure generic responses to RCPT TO for invalid recipient addresses.",
            "pop3_plaintext_auth": "Enforce TLS (STLS or POP3S on port 995) and disable plaintext USER/PASS authentication over unencrypted channels.",
            "imap_anonymous_login": "Require SASL/PLAIN authentication over TLS (STARTTLS or IMAPS on port 993) and disable anonymous IMAP access.",
            "irc_unauthenticated_operator": "Require oper passwords with strong hashing and restrict OPER command access by IP and TLS client certs.",
            "rabbitmq_guest_default_creds": "Delete or disable default 'guest'/'guest' account and enforce strong per-application vhost credentials.",
            "rabbitmq_open_management": "Restrict RabbitMQ Management UI (port 15672) to internal management subnets and disable default guest web login.",
            "nats_unauthenticated_cluster": "Enable token, user/password, or NKey authentication in nats-server configuration and isolate port 4222.",
            "ibmmq_blank_channel": "Set MCAUSER on SVRCONN channels to a low-privilege user; block blank or SYSTEM channels from administrative access.",
            "kafka_unauthenticated_broker": "Enable SASL/SCRAM or mTLS authentication in server.properties (listeners=SASL_PLAINTEXT or SSL) and enforce ACLs.",
            "mqtt_anonymous_read_write": "Set allow_anonymous false in mosquitto.conf and require client authentication/TLS for MQTT pub/sub.",
        }
        return guidance_map.get(
            self.finding_type,
            f"Harden authentication and access boundaries for {self.service_type.upper()} messaging service."
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessagingPrivilegeCandidate:
        return cls(
            candidate_id=data["candidate_id"],
            service_type=data["service_type"],
            category=data["category"],
            target_host=data["target_host"],
            port=data["port"],
            vantage=data.get("vantage", "external"),
            finding_type=data.get("finding_type", "unauthenticated_messaging"),
            auth_prerequisites=data.get("auth_prerequisites", MessagingAuthPrerequisite.NONE.value),
            privilege_impact=data.get("privilege_impact", MessagingPrivilegeImpact.MESSAGE_TAMPERING.value),
            affected_role=data.get("affected_role", "anonymous"),
            applicable_versions=list(data.get("applicable_versions", [])),
            supporting_evidence=dict(data.get("supporting_evidence", {})),
            evidence_hash=data.get("evidence_hash", ""),
            remediation_guidance=data.get("remediation_guidance", ""),
        )


@dataclass
class CleanupReceipt:
    """A record of cleanup evidence, with its source and verification status."""

    receipt_id: str
    target_host: str
    service_type: str
    artifact_type: str
    artifact_identifier: str
    action_taken: str = "unverified"
    verified_clean: bool = False
    evidence_source: str = "unspecified"
    receipt_hash: str = ""
    timestamp_utc: str = field(default_factory=utc_now)
    delivered_at_utc: str | None = None
    retention_started_at_utc: str | None = None
    retention_seconds: int | None = None

    def __post_init__(self) -> None:
        _literal_bool(self.verified_clean, "verified_clean")
        cleanup_at = _aware_timestamp(self.timestamp_utc, "timestamp_utc")
        if cleanup_at > datetime.now(timezone.utc):
            raise ValueError("Cleanup timestamp cannot be in the future")
        delivered_at = None
        if self.delivered_at_utc is not None:
            delivered_at = _aware_timestamp(self.delivered_at_utc, "delivered_at_utc")
            if delivered_at > cleanup_at:
                raise ValueError("Cleanup cannot precede canary delivery")
        if (self.retention_started_at_utc is None) != (self.retention_seconds is None):
            raise ValueError("Cleanup retention start and duration must be supplied together")
        if self.retention_started_at_utc is not None:
            retention_start = _aware_timestamp(self.retention_started_at_utc, "retention_started_at_utc")
            retention_seconds = _literal_int(self.retention_seconds, "retention_seconds")
            if not 0 < retention_seconds <= 86400:
                raise ValueError("Cleanup retention must be between 1 and 86400 seconds")
            if (
                delivered_at is None
                or not retention_start <= delivered_at <= cleanup_at
                or cleanup_at >= retention_start + timedelta(seconds=retention_seconds)
            ):
                raise ValueError("Cleanup must follow delivery within the retention window")
        if self.action_taken == "synthetic_fixture_cleanup_confirmed" and self.verified_clean:
            if (
                self.evidence_source != "synthetic_fixture"
                or delivered_at is None
                or self.retention_started_at_utc is None
            ):
                raise ValueError("Verified synthetic cleanup requires timestamped, bounded fixture evidence")
            if not isinstance(self.artifact_identifier, str) or not self.artifact_identifier.strip():
                raise ValueError("Verified synthetic cleanup requires a canary identifier")
        expected_hash = self._compute_hash()
        if self.receipt_hash:
            if not isinstance(self.receipt_hash, str) or not hmac.compare_digest(
                self.receipt_hash, expected_hash
            ):
                raise ValueError("Cleanup receipt hash does not match its contents")
        else:
            self.receipt_hash = expected_hash

    def _compute_hash(self) -> str:
        payload = {
            "receipt_id": self.receipt_id,
            "target_host": self.target_host,
            "service_type": self.service_type,
            "artifact_type": self.artifact_type,
            "artifact_identifier": self.artifact_identifier,
            "action_taken": self.action_taken,
            "verified_clean": self.verified_clean,
            "evidence_source": self.evidence_source,
            "timestamp_utc": self.timestamp_utc,
            "delivered_at_utc": self.delivered_at_utc,
        }
        if self.retention_started_at_utc is not None:
            payload["retention_started_at_utc"] = self.retention_started_at_utc
            payload["retention_seconds"] = self.retention_seconds
        canonical_blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical_blob).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CleanupReceipt:
        if not isinstance(data, dict) or not data.get("receipt_hash"):
            raise ValueError("Cleanup receipt must include an integrity hash")
        return cls(
            receipt_id=data["receipt_id"],
            target_host=data["target_host"],
            service_type=data["service_type"],
            artifact_type=data["artifact_type"],
            artifact_identifier=data["artifact_identifier"],
            action_taken=data.get("action_taken", "unverified"),
            verified_clean=_literal_bool(data.get("verified_clean", False), "verified_clean"),
            evidence_source=data.get("evidence_source", "unspecified"),
            receipt_hash=data.get("receipt_hash", ""),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
            delivered_at_utc=data.get("delivered_at_utc"),
            retention_started_at_utc=data.get("retention_started_at_utc"),
            retention_seconds=data.get("retention_seconds"),
        )


@dataclass
class MessagingServiceAssessment:
    """Discrete security assessment for one mail, chat, or message broker service endpoint."""

    target_host: str
    resolved_ip: str
    service_type: str
    category: str
    port: int
    protocol: str = "tcp"
    vantage: str = "external"
    exposure_status: str = MessagingExposureStatus.INACCESSIBLE.value
    canary_validated: bool = False
    canary_identifier: str | None = None
    authentication_required: bool | None = None
    auth_prerequisite: str = MessagingAuthPrerequisite.UNKNOWN.value
    assigned_role: str = "unknown"
    message_budget_limit: int = 5
    messages_sent_or_observed: int = 0
    tls_enforced: bool | None = None
    relay_tested: bool = False
    relay_permitted: bool = False
    applicable_versions: list[str] = field(default_factory=list)
    configuration_details: dict[str, Any] = field(default_factory=dict)
    observed_vulnerabilities: list[str] = field(default_factory=list)
    uncertainty_notes: list[str] = field(default_factory=list)
    privilege_candidates: list[MessagingPrivilegeCandidate] = field(default_factory=list)
    cleanup_receipts: list[CleanupReceipt] = field(default_factory=list)
    error_message: str | None = None
    timestamp_utc: str = field(default_factory=utc_now)
    provenance: EvidenceProvenance | None = None

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        if self.provenance:
            res["provenance"] = self.provenance.to_dict()
        res["privilege_candidates"] = [c.to_dict() for c in self.privilege_candidates]
        res["cleanup_receipts"] = [r.to_dict() for r in self.cleanup_receipts]
        return res

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessagingServiceAssessment:
        prov = EvidenceProvenance.from_dict(data["provenance"]) if data.get("provenance") else None
        candidates = [MessagingPrivilegeCandidate.from_dict(c) for c in data.get("privilege_candidates", [])]
        receipts = [CleanupReceipt.from_dict(r) for r in data.get("cleanup_receipts", [])]
        canary_validated = _literal_bool(data.get("canary_validated", False), "canary_validated")
        message_budget_limit = _literal_int(data.get("message_budget_limit", 5), "message_budget_limit")
        messages_sent_or_observed = _literal_int(
            data.get("messages_sent_or_observed", 0), "messages_sent_or_observed"
        )
        if not 0 <= message_budget_limit <= 5:
            raise ValueError("message_budget_limit must be between 0 and 5")
        if messages_sent_or_observed < 0:
            raise ValueError("messages_sent_or_observed cannot be negative")
        if canary_validated and not 0 < messages_sent_or_observed <= message_budget_limit:
            raise ValueError("Validated canary exceeds or lacks its message budget")
        if canary_validated and (
            not isinstance(data.get("canary_identifier"), str)
            or not data["canary_identifier"].strip()
        ):
            raise ValueError("Validated canary requires a canary identifier")
        return cls(
            target_host=data["target_host"],
            resolved_ip=data.get("resolved_ip", data["target_host"]),
            service_type=data["service_type"],
            category=data["category"],
            port=data["port"],
            protocol=data.get("protocol", "tcp"),
            vantage=data.get("vantage", "external"),
            exposure_status=data.get("exposure_status", MessagingExposureStatus.INACCESSIBLE.value),
            canary_validated=canary_validated,
            canary_identifier=data.get("canary_identifier"),
            authentication_required=_optional_literal_bool(data.get("authentication_required"), "authentication_required"),
            auth_prerequisite=data.get("auth_prerequisite", MessagingAuthPrerequisite.UNKNOWN.value),
            assigned_role=data.get("assigned_role", "unknown"),
            message_budget_limit=message_budget_limit,
            messages_sent_or_observed=messages_sent_or_observed,
            tls_enforced=_optional_literal_bool(data.get("tls_enforced"), "tls_enforced"),
            relay_tested=_literal_bool(data.get("relay_tested", False), "relay_tested"),
            relay_permitted=_literal_bool(data.get("relay_permitted", False), "relay_permitted"),
            applicable_versions=list(data.get("applicable_versions", [])),
            configuration_details=dict(data.get("configuration_details", {})),
            observed_vulnerabilities=list(data.get("observed_vulnerabilities", [])),
            uncertainty_notes=list(data.get("uncertainty_notes", [])),
            privilege_candidates=candidates,
            cleanup_receipts=receipts,
            error_message=data.get("error_message"),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
            provenance=prov,
        )


@dataclass
class MessagingServicesReport:
    """Comprehensive discovery and assessment report across mail, chat, and broker services."""

    report_id: str
    target_scope: list[str]
    vantage: str = "external"
    assessments: list[MessagingServiceAssessment] = field(default_factory=list)
    total_probed: int = 0
    total_exposed: int = 0
    total_protected: int = 0
    total_inaccessible: int = 0
    total_misconfigured: int = 0
    candidates_count: int = 0
    cleanup_receipts_count: int = 0
    timestamp_utc: str = field(default_factory=utc_now)

    def summary(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target_scope": self.target_scope,
            "vantage": self.vantage,
            "total_probed": self.total_probed,
            "total_exposed": self.total_exposed,
            "total_protected": self.total_protected,
            "total_inaccessible": self.total_inaccessible,
            "total_misconfigured": self.total_misconfigured,
            "candidates_count": self.candidates_count,
            "cleanup_receipts_count": self.cleanup_receipts_count,
            "timestamp_utc": self.timestamp_utc,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target_scope": self.target_scope,
            "vantage": self.vantage,
            "total_probed": self.total_probed,
            "total_exposed": self.total_exposed,
            "total_protected": self.total_protected,
            "total_inaccessible": self.total_inaccessible,
            "total_misconfigured": self.total_misconfigured,
            "candidates_count": self.candidates_count,
            "cleanup_receipts_count": self.cleanup_receipts_count,
            "timestamp_utc": self.timestamp_utc,
            "assessments": [a.to_dict() for a in self.assessments],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessagingServicesReport:
        assessments = [MessagingServiceAssessment.from_dict(a) for a in data.get("assessments", [])]
        return cls(
            report_id=data["report_id"],
            target_scope=list(data.get("target_scope", [])),
            vantage=data.get("vantage", "external"),
            assessments=assessments,
            total_probed=data.get("total_probed", len(assessments)),
            total_exposed=data.get("total_exposed", 0),
            total_protected=data.get("total_protected", 0),
            total_inaccessible=data.get("total_inaccessible", 0),
            total_misconfigured=data.get("total_misconfigured", 0),
            candidates_count=data.get("candidates_count", 0),
            cleanup_receipts_count=data.get("cleanup_receipts_count", 0),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path | str) -> MessagingServicesReport:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)
