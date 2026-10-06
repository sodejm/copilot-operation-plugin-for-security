"""Data models and taxonomy for databases, caches, and search/analytics services."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cops.evidence.canonical import canonical, utc_now

from .models import EvidenceProvenance


class DataServiceCategory(str, Enum):
    """Broad category taxonomy for database, cache, and search services."""

    RELATIONAL_DB = "relational_db"
    NOSQL_DOCUMENT = "nosql_document"
    CACHE_INMEMORY = "cache_inmemory"
    SEARCH_ANALYTICS = "search_analytics"


class DataServiceType(str, Enum):
    """Specific protocol and engine taxonomy for databases, caches, and search engines."""

    # Relational Databases
    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"
    ORACLE = "oracle"

    # NoSQL & Document Stores
    MONGODB = "mongodb"
    COUCHDB = "couchdb"
    CASSANDRA = "cassandra"

    # In-Memory & Caches
    REDIS = "redis"
    MEMCACHED = "memcached"

    # Search & Analytics Engines
    ELASTICSEARCH = "elasticsearch"
    INFLUXDB = "influxdb"
    KIBANA = "kibana"
    SPLUNK = "splunk"


class DataExposureStatus(str, Enum):
    """Reachability and exposure posture for databases, caches, and search services."""

    EXPOSED = "exposed"
    PROTECTED = "protected"
    INACCESSIBLE = "inaccessible"
    MISCONFIGURED = "misconfigured"
    REMEDIATED = "remediated"


class DataAuthPrerequisite(str, Enum):
    """Authentication and boundary prerequisite required to interact with data service."""

    NONE = "none"
    ANONYMOUS = "anonymous"
    DEFAULT_CREDENTIALS = "default_credentials"
    USER_PASSWORD = "user_password"  # noqa: S105 - schema label or operation identifier, not a credential
    CLIENT_CERT = "client_cert"
    TOKEN_OR_API_KEY = "token_or_api_key"  # noqa: S105 - schema label or operation identifier, not a credential
    KERBEROS = "kerberos"
    UNKNOWN = "unknown"


class DataPrivilegeImpact(str, Enum):
    """Security and lateral movement impact of an exposed or misconfigured data service."""

    REMOTE_CODE_EXECUTION = "remote_code_execution"
    DATABASE_TAKEOVER = "database_takeover"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    DATA_EXFILTRATION = "data_exfiltration"
    CACHE_POISONING = "cache_poisoning"
    ANALYTICS_TAMPERING = "analytics_tampering"
    NONE = "none"


@dataclass
class DataPrivilegeCandidate:
    """Actionable finding for database takeover, lateral movement, or data exfiltration."""

    candidate_id: str
    service_type: str
    category: str
    target_host: str
    port: int
    vantage: str = "external"
    finding_type: str = "unauthenticated_database"
    auth_prerequisites: str = DataAuthPrerequisite.NONE.value
    privilege_impact: str = DataPrivilegeImpact.DATA_EXFILTRATION.value
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
            "redis_no_auth": "Require strong authentication via 'requirepass' in redis.conf and disable dangerous commands (CONFIG, FLUSHALL).",
            "redis_config_set": "Rename or disable CONFIG command and restrict network access to trusted application servers.",
            "elasticsearch_open_cluster": "Enable Elasticsearch security features (xpack.security.enabled: true) and require native/LDAP authentication.",
            "mongodb_no_auth": "Enable mandatory authorization (--auth) and bind MongoDB strictly to 127.0.0.1 or an internal VPC network.",
            "memcached_no_auth": "Bind Memcached exclusively to localhost (-l 127.0.0.1) or firewall port 11211; disable UDP if not needed.",
            "mysql_no_auth": "Set strong passwords for root and administrative accounts; disable remote root login.",
            "postgres_trust_auth": "Change pg_hba.conf authentication method from 'trust' to 'scram-sha-256' or 'cert'.",
            "mssql_blank_sa": "Enforce complex sa account password and disable xp_cmdshell extended stored procedures.",
            "couchdb_admin_party": "Create administrative user account to terminate CouchDB Admin Party mode.",
            "cassandra_default_superuser": "Change default cassandra superuser password and configure PasswordAuthenticator in cassandra.yaml.",
            "influxdb_no_auth": "Enable auth-enabled = true in influxdb.conf and create admin user before opening network port.",
            "kibana_no_auth": "Configure Kibana Spaces and Elasticsearch native security integration.",
            "splunk_default_creds": "Change default admin credentials and enforce TLS with valid certificates on management port 8089.",
        }
        return guidance_map.get(
            self.finding_type,
            f"Harden authentication and network isolation for {self.service_type.upper()} service."
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DataPrivilegeCandidate:
        return cls(
            candidate_id=data["candidate_id"],
            service_type=data["service_type"],
            category=data["category"],
            target_host=data["target_host"],
            port=data["port"],
            vantage=data.get("vantage", "external"),
            finding_type=data.get("finding_type", "unauthenticated_database"),
            auth_prerequisites=data.get("auth_prerequisites", DataAuthPrerequisite.NONE.value),
            privilege_impact=data.get("privilege_impact", DataPrivilegeImpact.DATA_EXFILTRATION.value),
            affected_role=data.get("affected_role", "anonymous"),
            applicable_versions=list(data.get("applicable_versions", [])),
            supporting_evidence=dict(data.get("supporting_evidence", {})),
            evidence_hash=data.get("evidence_hash", ""),
            remediation_guidance=data.get("remediation_guidance", ""),
        )


@dataclass
class CleanupReceipt:
    """Verifiable proof of non-destructive canary test cleanup."""

    receipt_id: str
    target_host: str
    service_type: str
    artifact_type: str
    artifact_identifier: str
    action_taken: str = "verified_removed"
    verified_clean: bool = True
    receipt_hash: str = ""
    timestamp_utc: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.receipt_hash:
            canonical_blob = f"{self.receipt_id}:{self.target_host}:{self.service_type}:{self.artifact_identifier}:{self.action_taken}".encode()
            self.receipt_hash = hashlib.sha256(canonical_blob).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CleanupReceipt:
        return cls(
            receipt_id=data["receipt_id"],
            target_host=data["target_host"],
            service_type=data["service_type"],
            artifact_type=data["artifact_type"],
            artifact_identifier=data["artifact_identifier"],
            action_taken=data.get("action_taken", "verified_removed"),
            verified_clean=bool(data.get("verified_clean", True)),
            receipt_hash=data.get("receipt_hash", ""),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )


@dataclass
class DataServiceAssessment:
    """Discrete security assessment for one database, cache, or search engine endpoint."""

    target_host: str
    resolved_ip: str
    service_type: str
    category: str
    port: int
    protocol: str = "tcp"
    vantage: str = "external"
    exposure_status: str = DataExposureStatus.INACCESSIBLE.value
    canary_validated: bool = False
    canary_identifier: str | None = None
    authentication_required: bool | None = None
    auth_prerequisite: str = DataAuthPrerequisite.UNKNOWN.value
    assigned_role: str = "unknown"
    query_budget_rows: int = 5
    applicable_versions: list[str] = field(default_factory=list)
    configuration_details: dict[str, Any] = field(default_factory=dict)
    observed_vulnerabilities: list[str] = field(default_factory=list)
    uncertainty_notes: list[str] = field(default_factory=list)
    privilege_candidates: list[DataPrivilegeCandidate] = field(default_factory=list)
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
    def from_dict(cls, data: dict[str, Any]) -> DataServiceAssessment:
        prov = EvidenceProvenance.from_dict(data["provenance"]) if data.get("provenance") else None
        candidates = [DataPrivilegeCandidate.from_dict(c) for c in data.get("privilege_candidates", [])]
        receipts = [CleanupReceipt.from_dict(r) for r in data.get("cleanup_receipts", [])]
        return cls(
            target_host=data["target_host"],
            resolved_ip=data.get("resolved_ip", data["target_host"]),
            service_type=data["service_type"],
            category=data["category"],
            port=data["port"],
            protocol=data.get("protocol", "tcp"),
            vantage=data.get("vantage", "external"),
            exposure_status=data.get("exposure_status", DataExposureStatus.INACCESSIBLE.value),
            canary_validated=bool(data.get("canary_validated", False)),
            canary_identifier=data.get("canary_identifier"),
            authentication_required=data.get("authentication_required"),
            auth_prerequisite=data.get("auth_prerequisite", DataAuthPrerequisite.UNKNOWN.value),
            assigned_role=data.get("assigned_role", "unknown"),
            query_budget_rows=data.get("query_budget_rows", 5),
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
class DataServicesReport:
    """Evaluation report across databases, caches, and search/analytics services."""

    report_id: str
    scope_reference: str
    vantage: str = "external"
    services_assessed: list[DataServiceAssessment] = field(default_factory=list)
    privilege_candidates: list[DataPrivilegeCandidate] = field(default_factory=list)
    cleanup_receipts: list[CleanupReceipt] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    timestamp_utc: str = field(default_factory=utc_now)

    @property
    def total_assessed(self) -> int:
        return len(self.services_assessed)

    @property
    def total_exposed(self) -> int:
        return self.summary.get("exposed", 0)

    @property
    def total_inaccessible(self) -> int:
        return self.summary.get("inaccessible", 0)

    @property
    def total_protected(self) -> int:
        return self.summary.get("protected", 0)

    @property
    def total_remediated(self) -> int:
        return self.summary.get("remediated", 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "scope_reference": self.scope_reference,
            "vantage": self.vantage,
            "services_assessed": [s.to_dict() for s in self.services_assessed],
            "privilege_candidates": [c.to_dict() for c in self.privilege_candidates],
            "cleanup_receipts": [r.to_dict() for r in self.cleanup_receipts],
            "summary": dict(self.summary),
            "timestamp_utc": self.timestamp_utc,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DataServicesReport:
        return cls(
            report_id=data["report_id"],
            scope_reference=data["scope_reference"],
            vantage=data.get("vantage", "external"),
            services_assessed=[DataServiceAssessment.from_dict(s) for s in data.get("services_assessed", [])],
            privilege_candidates=[DataPrivilegeCandidate.from_dict(c) for c in data.get("privilege_candidates", [])],
            cleanup_receipts=[CleanupReceipt.from_dict(r) for r in data.get("cleanup_receipts", [])],
            summary=dict(data.get("summary", {})),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(canonical(self.to_dict()) + b"\n")

    save_to_file = save

    @classmethod
    def load(cls, path: Path | str) -> DataServicesReport:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    load_from_file = load

