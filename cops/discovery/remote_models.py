"""Data models and taxonomy for remote administration, file sharing, and print services."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cops.evidence.canonical import canonical, utc_now

from .models import EvidenceProvenance


class RemoteServiceCategory(str, Enum):
    """Broad category taxonomy for remote, file, and print services."""

    REMOTE_ADMIN = "remote_admin"
    FILE_SHARING = "file_sharing"
    PRINTING = "printing"


class RemoteServiceType(str, Enum):
    """Specific protocol taxonomy for remote, file, and print services."""

    # Remote Administration
    SSH = "ssh"
    TELNET = "telnet"
    RDP = "rdp"
    VNC = "vnc"
    WINRM = "winrm"
    X11 = "x11"

    # File Sharing
    SMB = "smb"
    NFS = "nfs"
    FTP = "ftp"
    TFTP = "tftp"
    RSYNC = "rsync"
    AFP = "afp"

    # Printing
    LPD = "lpd"
    IPP = "ipp"
    RAW_PRINT = "raw_print"


class RemoteExposureStatus(str, Enum):
    """Evaluation status of service exposure."""

    EXPOSED = "exposed"
    PROTECTED = "protected"
    INACCESSIBLE = "inaccessible"
    MISCONFIGURED = "misconfigured"
    REMEDIATED = "remediated"


class RemoteAuthPrerequisite(str, Enum):
    """Authentication and privilege prerequisite requirements."""

    NONE = "none"
    ANONYMOUS = "anonymous"
    DEFAULT_CREDENTIALS = "default_credentials"
    USER_PASSWORD = "user_password"  # noqa: S105 - schema label or operation identifier, not a credential
    PUBLIC_KEY = "public_key"
    NLA_REQUIRED = "nla_required"
    KERBEROS = "kerberos"
    UNKNOWN = "unknown"


class LateralMovementImpact(str, Enum):
    """Potential offensive impact on target host and lateral movement."""

    COMMAND_EXECUTION = "command_execution"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_PRINTING = "unauthorized_printing"
    NONE = "none"


@dataclass
class HostPrivilegeCandidate:
    """Actionable privilege or lateral movement finding routed to host specialist workflows."""

    candidate_id: str
    service_type: str
    category: str
    target_host: str
    port: int
    vantage: str
    finding_type: str
    auth_prerequisites: str
    lateral_movement_impact: str
    applicable_versions: list[str] = field(default_factory=list)
    supporting_evidence: dict[str, Any] = field(default_factory=dict)
    remediation_guidance: str = ""
    evidence_hash: str = ""
    timestamp_utc: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.evidence_hash:
            h = hashlib.sha256(
                f"{self.candidate_id}:{self.target_host}:{self.port}:{self.service_type}:{self.finding_type}:{self.auth_prerequisites}".encode()
            ).hexdigest()
            self.evidence_hash = h
        if not self.remediation_guidance:
            guidance_map = {
                "smb_unauthenticated_share": "Disable guest and null session access on SMB shares; restrict sensitive administrative shares (C$, ADMIN$).",
                "smb_v1_enabled": "Disable obsolete SMBv1/CIFS protocol across all endpoints and enforce SMBv2/v3.",
                "smb_signing_disabled": "Enforce SMB packet signing (RequireSecuritySignature=true) to prevent relay and spoofing attacks.",
                "rdp_nla_disabled": "Enforce Network Level Authentication (NLA) on Remote Desktop services to prevent pre-authentication exploitation.",
                "vnc_no_auth": "Require strong authentication password or TLS mutual authentication on VNC RFB endpoints.",
                "telnet_plaintext_exposure": "Decommission unencrypted Telnet service and migrate administrative access to SSH with public key authentication.",
                "winrm_http_unencrypted": "Disable plaintext WinRM HTTP (5985) and mandate HTTPS (5986) with certificate validation.",
                "x11_open_display": "Bind X11 display server to localhost only (nolisten tcp) and require MIT-MAGIC-COOKIE authorization.",
                "nfs_no_root_squash": "Enable 'root_squash' on NFS export configurations and restrict exports to authorized client subnets.",
                "ftp_anonymous_login": "Disable anonymous FTP access and migrate file transfer services to SFTP or FTPS.",
                "rsync_open_module": "Enforce 'auth users' and secrets file for all rsync daemon modules; restrict host access via 'hosts allow'.",
                "afp_guest_access": "Disable unauthenticated Guest UAM on Apple Filing Protocol shares.",
                "unauthenticated_printer_queue": "Enforce printer access control lists (ACLs) and require authentication on IPP/LPD queues.",
            }
            self.remediation_guidance = guidance_map.get(
                self.finding_type, "Enforce strong authentication, disable legacy protocols, and restrict network segmentation."
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HostPrivilegeCandidate:
        return cls(
            candidate_id=data["candidate_id"],
            service_type=data["service_type"],
            category=data["category"],
            target_host=data["target_host"],
            port=int(data["port"]),
            vantage=data["vantage"],
            finding_type=data["finding_type"],
            auth_prerequisites=data.get("auth_prerequisites", RemoteAuthPrerequisite.UNKNOWN.value),
            lateral_movement_impact=data.get("lateral_movement_impact", LateralMovementImpact.NONE.value),
            applicable_versions=list(data.get("applicable_versions", [])),
            supporting_evidence=dict(data.get("supporting_evidence", {})),
            remediation_guidance=data.get("remediation_guidance", ""),
            evidence_hash=data.get("evidence_hash", ""),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )


@dataclass
class CleanupReceipt:
    """Verifiable proof of assessment-created artifact removal or rollback."""

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
            h = hashlib.sha256(
                f"{self.receipt_id}:{self.target_host}:{self.service_type}:{self.artifact_type}:{self.artifact_identifier}:{self.action_taken}".encode()
            ).hexdigest()
            self.receipt_hash = h

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
class RemoteServiceAssessment:
    """Discrete assessment record for remote administration, file sharing, or print services."""

    target_host: str
    resolved_ip: str
    service_type: str
    category: str
    port: int
    protocol: str = "tcp"
    vantage: str = "external"
    exposure_status: str = RemoteExposureStatus.INACCESSIBLE.value
    canary_validated: bool = False
    canary_identifier: str | None = None
    authentication_required: bool | None = None
    auth_prerequisite: str = RemoteAuthPrerequisite.UNKNOWN.value
    applicable_versions: list[str] = field(default_factory=list)
    is_legacy_or_unencrypted: bool = False
    configuration_details: dict[str, Any] = field(default_factory=dict)
    observed_vulnerabilities: list[str] = field(default_factory=list)
    uncertainty_notes: list[str] = field(default_factory=list)
    host_privilege_candidates: list[HostPrivilegeCandidate] = field(default_factory=list)
    cleanup_receipts: list[CleanupReceipt] = field(default_factory=list)
    error_message: str | None = None
    timestamp_utc: str = field(default_factory=utc_now)
    provenance: EvidenceProvenance | None = None

    @property
    def protocol_details(self) -> dict[str, Any]:
        return self.configuration_details

    @property
    def candidates(self) -> list[HostPrivilegeCandidate]:
        return list(self.host_privilege_candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_host": self.target_host,
            "resolved_ip": self.resolved_ip,
            "service_type": self.service_type,
            "category": self.category,
            "port": self.port,
            "protocol": self.protocol,
            "vantage": self.vantage,
            "exposure_status": self.exposure_status,
            "canary_validated": self.canary_validated,
            "canary_identifier": self.canary_identifier,
            "authentication_required": self.authentication_required,
            "auth_prerequisite": self.auth_prerequisite,
            "applicable_versions": list(self.applicable_versions),
            "is_legacy_or_unencrypted": self.is_legacy_or_unencrypted,
            "configuration_details": dict(self.configuration_details),
            "observed_vulnerabilities": list(self.observed_vulnerabilities),
            "uncertainty_notes": list(self.uncertainty_notes),
            "host_privilege_candidates": [c.to_dict() for c in self.host_privilege_candidates],
            "cleanup_receipts": [r.to_dict() for r in self.cleanup_receipts],
            "error_message": self.error_message,
            "timestamp_utc": self.timestamp_utc,
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemoteServiceAssessment:
        candidates = [
            HostPrivilegeCandidate.from_dict(c) for c in data.get("host_privilege_candidates", [])
        ]
        receipts = [
            CleanupReceipt.from_dict(r) for r in data.get("cleanup_receipts", [])
        ]
        prov = (
            EvidenceProvenance.from_dict(data["provenance"])
            if data.get("provenance")
            else None
        )
        return cls(
            target_host=data["target_host"],
            resolved_ip=data["resolved_ip"],
            service_type=data["service_type"],
            category=data["category"],
            port=int(data["port"]),
            protocol=data.get("protocol", "tcp"),
            vantage=data.get("vantage", "external"),
            exposure_status=data.get("exposure_status", RemoteExposureStatus.INACCESSIBLE.value),
            canary_validated=bool(data.get("canary_validated", False)),
            canary_identifier=data.get("canary_identifier"),
            authentication_required=data.get("authentication_required"),
            auth_prerequisite=data.get("auth_prerequisite", RemoteAuthPrerequisite.UNKNOWN.value),
            applicable_versions=list(data.get("applicable_versions", [])),
            is_legacy_or_unencrypted=bool(data.get("is_legacy_or_unencrypted", False)),
            configuration_details=dict(data.get("configuration_details", {})),
            observed_vulnerabilities=list(data.get("observed_vulnerabilities", [])),
            uncertainty_notes=list(data.get("uncertainty_notes", [])),
            host_privilege_candidates=candidates,
            cleanup_receipts=receipts,
            error_message=data.get("error_message"),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
            provenance=prov,
        )


@dataclass
class RemoteServicesReport:
    """Evaluation report across remote administration, file sharing, and print services."""

    report_id: str
    scope_reference: str
    vantage: str = "external"
    services_assessed: list[RemoteServiceAssessment] = field(default_factory=list)
    host_privilege_candidates: list[HostPrivilegeCandidate] = field(default_factory=list)
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

    @property
    def total_misconfigured(self) -> int:
        return self.summary.get("misconfigured", 0)

    @property
    def all_privilege_candidates(self) -> list[HostPrivilegeCandidate]:
        return list(self.host_privilege_candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "scope_reference": self.scope_reference,
            "vantage": self.vantage,
            "services_assessed": [s.to_dict() for s in self.services_assessed],
            "host_privilege_candidates": [c.to_dict() for c in self.host_privilege_candidates],
            "cleanup_receipts": [r.to_dict() for r in self.cleanup_receipts],
            "summary": dict(self.summary),
            "timestamp_utc": self.timestamp_utc,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemoteServicesReport:
        return cls(
            report_id=data["report_id"],
            scope_reference=data["scope_reference"],
            vantage=data.get("vantage", "external"),
            services_assessed=[RemoteServiceAssessment.from_dict(s) for s in data.get("services_assessed", [])],
            host_privilege_candidates=[HostPrivilegeCandidate.from_dict(c) for c in data.get("host_privilege_candidates", [])],
            cleanup_receipts=[CleanupReceipt.from_dict(r) for r in data.get("cleanup_receipts", [])],
            summary=dict(data.get("summary", {})),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(canonical(self.to_dict()) + b"\n")

    @classmethod
    def load(cls, path: Path | str) -> RemoteServicesReport:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)
