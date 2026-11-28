"""Data models and taxonomy for developer and runtime interfaces."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cops.evidence.canonical import utc_now

from .models import EvidenceProvenance


class DeveloperCategory(str, Enum):
    """Broad category taxonomy for developer and runtime interface services."""

    CONTAINER_ORCHESTRATION_RUNTIME = "container_orchestration_runtime"
    LANGUAGE_DEBUG_RUNTIME = "language_debug_runtime"
    DISTRIBUTED_BUILD_SCM = "distributed_build_scm"
    APPLICATION_SERVER_GATEWAY = "application_server_gateway"


class DeveloperServiceType(str, Enum):
    """Specific protocol and runtime taxonomy for developer interfaces."""

    # Container & Orchestration Runtimes
    DOCKER = "docker"
    DOCKER_REGISTRY = "docker_registry"

    # Language & Debugging Runtimes
    RMI = "rmi"
    JDWP = "jdwp"
    ERLANG_EPMD = "erlang_epmd"
    ADB = "adb"

    # Distributed Build & SCM
    DISTCC = "distcc"
    SVN = "svn"

    # Application Server & Gateway Interfaces
    AJP = "ajp"
    FASTCGI = "fastcgi"


class DeveloperExposureStatus(str, Enum):
    """Reachability and exposure posture for developer and runtime interfaces."""

    EXPOSED = "exposed"
    PROTECTED = "protected"
    INACCESSIBLE = "inaccessible"
    MISCONFIGURED = "misconfigured"
    REMEDIATED = "remediated"


class DeveloperAuthPrerequisite(str, Enum):
    """Authentication and boundary prerequisite required to interact with developer interface."""

    NONE = "none"
    ANONYMOUS = "anonymous"
    DEFAULT_CREDENTIALS = "default_credentials"
    USER_PASSWORD = "user_password"  # noqa: S105 - schema label or operation identifier, not a credential
    CLIENT_CERT = "client_cert"
    TOKEN_OR_API_KEY = "token_or_api_key"  # noqa: S105 - schema label or operation identifier, not a credential
    ERLANG_COOKIE = "erlang_cookie"
    UNKNOWN = "unknown"


class DeveloperPrivilegeImpact(str, Enum):
    """Security and operational impact of an exposed developer interface."""

    REMOTE_CODE_EXECUTION = "remote_code_execution"
    CONTAINER_ESCAPE = "container_escape"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    SOURCE_CODE_LEAKAGE = "source_code_leakage"
    FILE_INCLUSION = "file_inclusion"
    DATA_EXFILTRATION = "data_exfiltration"
    NONE = "none"


class ExecutionEffect(str, Enum):
    """Explicit declaration of operation effect on the target system."""

    READ_ONLY = "read_only"
    NON_DESTRUCTIVE = "non_destructive"
    STATE_CHANGE = "state_change"
    CODE_EXECUTION = "code_execution"


@dataclass
class DeveloperPrivilegeCandidate:
    """Actionable finding for code execution, container breakout, or source code leakage."""

    candidate_id: str
    service_type: str
    category: str
    target_host: str
    port: int
    vantage: str = "external"
    finding_type: str = "unauthenticated_developer_interface"
    auth_prerequisites: str = DeveloperAuthPrerequisite.NONE.value
    privilege_impact: str = DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value
    execution_effect: str = ExecutionEffect.CODE_EXECUTION.value
    affected_role: str = "anonymous"
    applicable_versions: list[str] = field(default_factory=list)
    supporting_evidence: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str = ""
    remediation_guidance: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_hash:
            canonical_blob = f"{self.service_type}:{self.target_host}:{self.port}:{self.finding_type}:{self.auth_prerequisites}:{self.privilege_impact}:{self.execution_effect}".encode()
            self.evidence_hash = hashlib.sha256(canonical_blob).hexdigest()
        if not self.remediation_guidance:
            self.remediation_guidance = self._default_remediation()

    def _default_remediation(self) -> str:
        guidance_map = {
            "docker_socket_rce": "Bind Docker daemon strictly to local Unix socket (/var/run/docker.sock) or require mutual TLS (TLSVerify) with client certificates on port 2376.",
            "docker_registry_leak": "Enable authentication (htpasswd or OAuth2 token server) and TLS on Docker Registry port 5000.",
            "rmi_code_execution": "Disable unauthenticated JMX/RMI registries or configure TLS and strong authentication with java.rmi.server.useCodebaseOnly=true.",
            "jdwp_code_execution": "Never expose JDWP debugging ports to external interfaces; terminate debug agent or bind strictly to 127.0.0.1 in non-production environments.",
            "erlang_epmd_rce": "Firewall Erlang Port Mapper Daemon (port 4369) and node distribution ports; require high-entropy Erlang cookies.",
            "adb_shell_rce": "Disable wireless ADB debugging (adb tcpip) on production devices and require RSA host key authentication.",
            "distcc_rce": "Restrict distcc access using --allow CIDR flags or disable distccd service on unsegmented development networks.",
            "svn_anonymous_checkout": "Configure anon-access = none in svnserve.conf and enforce password/SASL authentication.",
            "ajp_ghostcat_rce": "Upgrade Apache Tomcat, configure secretRequired=\"true\" with strong secret on AJP connector, or disable AJP if unused.",
            "fastcgi_rce": "Bind FastCGI daemon (php-fpm) strictly to localhost (127.0.0.1:9000) or Unix domain socket; block external access.",
        }
        return guidance_map.get(
            self.finding_type,
            f"Harden authentication and network isolation for {self.service_type.upper()} developer interface."
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeveloperPrivilegeCandidate:
        return cls(
            candidate_id=data["candidate_id"],
            service_type=data["service_type"],
            category=data["category"],
            target_host=data["target_host"],
            port=data["port"],
            vantage=data.get("vantage", "external"),
            finding_type=data.get("finding_type", "unauthenticated_developer_interface"),
            auth_prerequisites=data.get("auth_prerequisites", DeveloperAuthPrerequisite.NONE.value),
            privilege_impact=data.get("privilege_impact", DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value),
            execution_effect=data.get("execution_effect", ExecutionEffect.CODE_EXECUTION.value),
            affected_role=data.get("affected_role", "anonymous"),
            applicable_versions=list(data.get("applicable_versions", [])),
            supporting_evidence=dict(data.get("supporting_evidence", {})),
            evidence_hash=data.get("evidence_hash", ""),
            remediation_guidance=data.get("remediation_guidance", ""),
        )


@dataclass
class CleanupReceipt:
    """Verifiable proof of non-destructive canary test artifact cleanup."""

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
class DeveloperServiceAssessment:
    """Discrete security assessment for one developer or runtime interface endpoint."""

    target_host: str
    resolved_ip: str
    service_type: str
    category: str
    port: int
    protocol: str = "tcp"
    vantage: str = "external"
    exposure_status: str = DeveloperExposureStatus.INACCESSIBLE.value
    canary_validated: bool = False
    canary_identifier: str | None = None
    authentication_required: bool | None = None
    auth_prerequisite: str = DeveloperAuthPrerequisite.UNKNOWN.value
    assigned_role: str = "unknown"
    can_execute_code: bool = False
    can_change_state: bool = False
    bound_to_plan: bool = True
    applicable_versions: list[str] = field(default_factory=list)
    configuration_details: dict[str, Any] = field(default_factory=dict)
    observed_vulnerabilities: list[str] = field(default_factory=list)
    uncertainty_notes: list[str] = field(default_factory=list)
    privilege_candidates: list[DeveloperPrivilegeCandidate] = field(default_factory=list)
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
    def from_dict(cls, data: dict[str, Any]) -> DeveloperServiceAssessment:
        prov = EvidenceProvenance.from_dict(data["provenance"]) if data.get("provenance") else None
        candidates = [DeveloperPrivilegeCandidate.from_dict(c) for c in data.get("privilege_candidates", [])]
        receipts = [CleanupReceipt.from_dict(r) for r in data.get("cleanup_receipts", [])]
        return cls(
            target_host=data["target_host"],
            resolved_ip=data.get("resolved_ip", data["target_host"]),
            service_type=data["service_type"],
            category=data["category"],
            port=data["port"],
            protocol=data.get("protocol", "tcp"),
            vantage=data.get("vantage", "external"),
            exposure_status=data.get("exposure_status", DeveloperExposureStatus.INACCESSIBLE.value),
            canary_validated=bool(data.get("canary_validated", False)),
            canary_identifier=data.get("canary_identifier"),
            authentication_required=data.get("authentication_required"),
            auth_prerequisite=data.get("auth_prerequisite", DeveloperAuthPrerequisite.UNKNOWN.value),
            assigned_role=data.get("assigned_role", "unknown"),
            can_execute_code=bool(data.get("can_execute_code", False)),
            can_change_state=bool(data.get("can_change_state", False)),
            bound_to_plan=bool(data.get("bound_to_plan", True)),
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
class DeveloperServicesReport:
    """Comprehensive discovery and assessment report across developer and runtime interfaces."""

    report_id: str
    target_scope: list[str]
    vantage: str = "external"
    assessments: list[DeveloperServiceAssessment] = field(default_factory=list)
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
    def from_dict(cls, data: dict[str, Any]) -> DeveloperServicesReport:
        assessments = [DeveloperServiceAssessment.from_dict(a) for a in data.get("assessments", [])]
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
    def load(cls, path: Path | str) -> DeveloperServicesReport:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)
