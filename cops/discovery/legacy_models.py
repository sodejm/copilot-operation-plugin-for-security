"""Data models and taxonomy for legacy enterprise, management, and proxy services."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any

from cops.evidence.canonical import canonical, utc_now
from .models import EvidenceProvenance


class LegacyCategory(str, Enum):
    """Broad category taxonomy for legacy enterprise, management, and proxy services."""

    ENTERPRISE_STORAGE_MANAGEMENT = "enterprise_storage_management"
    OUT_OF_BAND_HARDWARE_MANAGEMENT = "out_of_band_hardware_management"
    NETWORK_DEVICE_APPLIANCE_MANAGEMENT = "network_device_appliance_management"
    VPN_TUNNELING_SERVICES = "vpn_tunneling_services"
    PROXY_EGRESS_SERVICES = "proxy_egress_services"


class LegacyServiceType(str, Enum):
    """Specific protocol and runtime taxonomy for legacy enterprise and proxy services."""

    # Enterprise Storage & Data Management
    NDMP = "ndmp"
    ISCSI = "iscsi"

    # Out-of-Band & Hardware Management
    IPMI = "ipmi"

    # Network Device & Appliance Management
    CISCO_SMART_INSTALL = "cisco_smart_install"
    TACACS = "tacacs"

    # VPN & Tunneling Services
    IKE = "ike"
    PPTP = "pptp"

    # Proxy & Egress Services
    SOCKS = "socks"
    SQUID = "squid"


class LegacyExposureStatus(str, Enum):
    """Reachability and exposure posture for legacy and proxy services."""

    EXPOSED = "exposed"
    PROTECTED = "protected"
    INACCESSIBLE = "inaccessible"
    MISCONFIGURED = "misconfigured"
    REMEDIATED = "remediated"


class LegacyAuthPrerequisite(str, Enum):
    """Authentication prerequisite required to interact with legacy service."""

    NONE = "none"
    ANONYMOUS = "anonymous"
    CHAP = "chap"
    CIPHER_ZERO = "cipher_zero"
    RAKP_HASH = "rakp_hash"
    SHARED_KEY = "shared_key"
    PSK = "psk"
    MSCHAPV2 = "mschapv2"
    USER_PASSWORD = "user_password"
    ACL_RESTRICTED = "acl_restricted"
    UNKNOWN = "unknown"


class LegacyPrivilegeImpact(str, Enum):
    """Security and operational impact of an exposed legacy or proxy service."""

    STORAGE_TAKEOVER = "storage_takeover"
    HARDWARE_BMC_TAKEOVER = "hardware_bmc_takeover"
    DEVICE_RECONFIGURATION = "device_reconfiguration"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    PROXY_EGRESS_PIVOT = "proxy_egress_pivot"
    TRAFFIC_INTERCEPTION = "traffic_interception"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    NONE = "none"


class ExecutionEffect(str, Enum):
    """Explicit declaration of operation effect on the target system."""

    READ_ONLY = "read_only"
    NON_DESTRUCTIVE = "non_destructive"
    STATE_CHANGE = "state_change"
    CODE_EXECUTION = "code_execution"


@dataclass
class LegacyPrivilegeCandidate:
    """Actionable finding for storage takeover, BMC compromise, or proxy egress pivoting."""

    candidate_id: str
    service_type: str
    category: str
    target_host: str
    port: int
    vantage: str = "external"
    finding_type: str = "legacy_service_exposure"
    auth_prerequisites: str = LegacyAuthPrerequisite.NONE.value
    privilege_impact: str = LegacyPrivilegeImpact.PROXY_EGRESS_PIVOT.value
    execution_effect: str = ExecutionEffect.READ_ONLY.value
    affected_role: str = "anonymous"
    applicable_versions: list[str] = field(default_factory=list)
    supporting_evidence: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str = ""
    remediation_guidance: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_hash:
            canonical_blob = f"{self.service_type}:{self.target_host}:{self.port}:{self.finding_type}:{self.auth_prerequisites}:{self.privilege_impact}:{self.execution_effect}".encode("utf-8")
            self.evidence_hash = hashlib.sha256(canonical_blob).hexdigest()
        if not self.remediation_guidance:
            self.remediation_guidance = self._default_remediation()

    def _default_remediation(self) -> str:
        guidance_map = {
            "ndmp_unauthenticated_access": "Enable MD5/password authentication on NDMP port 10000 or firewall backup storage networks from unauthorized access.",
            "iscsi_unauthenticated_target": "Enable mutual CHAP (Challenge-Handshake Authentication Protocol) and bind iSCSI targets strictly to dedicated storage VLANs.",
            "ipmi_cipher_zero_bypass": "Disable Cipher 0 in IPMI BMC configuration and upgrade BMC firmware to enforce authenticated cipher suites (Cipher 3 or Cipher 17).",
            "ipmi_rakp_hash_dump": "Isolate IPMI/BMC interfaces to an out-of-band management network and enforce complex 16+ character BMC passwords resistant to offline dictionary attacks.",
            "cisco_smart_install_rce": "Disable Cisco Smart Install using 'no vstack' in global configuration or block TCP port 4786 at network boundaries.",
            "tacacs_unauthenticated_daemon": "Enforce strong shared secret keys on TACACS+ daemons, upgrade to TACACS+ TLS (RFC 8907), and restrict client IP allowlists.",
            "ike_aggressive_mode_psk": "Disable IKEv1 Aggressive Mode; migrate to IKEv2 or require X.509 certificate authentication instead of pre-shared keys.",
            "pptp_mschapv2_exposure": "Decommission legacy PPTP VPN in favor of WireGuard, OpenVPN, or IPsec/IKEv2 to prevent MS-CHAPv2 credential cracking.",
            "socks_open_proxy": "Disable open SOCKS proxy relaying; configure username/password authentication (RFC 1929) and restrict destination egress networks.",
            "squid_open_proxy": "Configure strict Squid ACLs (http_access deny all) restricting proxy access to authorized client subnets and blocking internal metadata/loopback destinations.",
        }
        return guidance_map.get(
            self.finding_type,
            f"Harden authentication, access control, and network isolation for {self.service_type.upper()} legacy interface."
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LegacyPrivilegeCandidate:
        return cls(
            candidate_id=data["candidate_id"],
            service_type=data["service_type"],
            category=data["category"],
            target_host=data["target_host"],
            port=data["port"],
            vantage=data.get("vantage", "external"),
            finding_type=data.get("finding_type", "legacy_service_exposure"),
            auth_prerequisites=data.get("auth_prerequisites", LegacyAuthPrerequisite.NONE.value),
            privilege_impact=data.get("privilege_impact", LegacyPrivilegeImpact.PROXY_EGRESS_PIVOT.value),
            execution_effect=data.get("execution_effect", ExecutionEffect.READ_ONLY.value),
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
            canonical_blob = f"{self.receipt_id}:{self.target_host}:{self.service_type}:{self.artifact_identifier}:{self.action_taken}".encode("utf-8")
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
class LegacyServiceAssessment:
    """Discrete security assessment for one legacy enterprise, management, or proxy endpoint."""

    target_host: str
    resolved_ip: str
    service_type: str
    category: str
    port: int
    protocol: str = "tcp"
    vantage: str = "external"
    exposure_status: str = LegacyExposureStatus.INACCESSIBLE.value
    canary_validated: bool = False
    canary_identifier: str | None = None
    authentication_required: bool | None = None
    auth_prerequisite: str = LegacyAuthPrerequisite.UNKNOWN.value
    assigned_role: str = "unknown"
    can_execute_code: bool = False
    can_change_state: bool = False
    bound_to_plan: bool = True
    proxy_egress_tested: bool = False
    proxy_egress_restricted: bool | None = None
    applicable_versions: list[str] = field(default_factory=list)
    configuration_details: dict[str, Any] = field(default_factory=dict)
    observed_vulnerabilities: list[str] = field(default_factory=list)
    uncertainty_notes: list[str] = field(default_factory=list)
    privilege_candidates: list[LegacyPrivilegeCandidate] = field(default_factory=list)
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
    def from_dict(cls, data: dict[str, Any]) -> LegacyServiceAssessment:
        prov = EvidenceProvenance.from_dict(data["provenance"]) if data.get("provenance") else None
        candidates = [LegacyPrivilegeCandidate.from_dict(c) for c in data.get("privilege_candidates", [])]
        receipts = [CleanupReceipt.from_dict(r) for r in data.get("cleanup_receipts", [])]
        return cls(
            target_host=data["target_host"],
            resolved_ip=data.get("resolved_ip", data["target_host"]),
            service_type=data["service_type"],
            category=data["category"],
            port=data["port"],
            protocol=data.get("protocol", "tcp"),
            vantage=data.get("vantage", "external"),
            exposure_status=data.get("exposure_status", LegacyExposureStatus.INACCESSIBLE.value),
            canary_validated=bool(data.get("canary_validated", False)),
            canary_identifier=data.get("canary_identifier"),
            authentication_required=data.get("authentication_required"),
            auth_prerequisite=data.get("auth_prerequisite", LegacyAuthPrerequisite.UNKNOWN.value),
            assigned_role=data.get("assigned_role", "unknown"),
            can_execute_code=bool(data.get("can_execute_code", False)),
            can_change_state=bool(data.get("can_change_state", False)),
            bound_to_plan=bool(data.get("bound_to_plan", True)),
            proxy_egress_tested=bool(data.get("proxy_egress_tested", False)),
            proxy_egress_restricted=data.get("proxy_egress_restricted"),
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
class LegacyServicesReport:
    """Comprehensive discovery and assessment report across legacy enterprise, management, and proxy services."""

    report_id: str
    target_scope: list[str]
    vantage: str = "external"
    assessments: list[LegacyServiceAssessment] = field(default_factory=list)
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
    def from_dict(cls, data: dict[str, Any]) -> LegacyServicesReport:
        assessments = [LegacyServiceAssessment.from_dict(a) for a in data.get("assessments", [])]
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
    def load(cls, path: Path | str) -> LegacyServicesReport:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)
