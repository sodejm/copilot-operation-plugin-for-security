"""Data models and contracts for infrastructure and identity-facing service assessment."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any

from cops.evidence.canonical import canonical, utc_now
from .models import EvidenceProvenance


class InfraServiceType(str, Enum):
    """Infrastructure and identity-facing service classifications."""

    DNS = "dns"
    MDNS = "mdns"
    SNMP = "snmp"
    NTP = "ntp"
    DISCOVERY = "discovery"
    RPC = "rpc"
    LDAP = "ldap"
    KERBEROS = "kerberos"


class ServiceExposureStatus(str, Enum):
    """Operational exposure status of assessed infrastructure service."""

    EXPOSED = "exposed"          # Service reachable, accepts unauthenticated or default access
    PROTECTED = "protected"      # Service reachable, actively enforces authentication or encryption
    INACCESSIBLE = "inaccessible" # Service not reachable from this vantage; NOT equivalent to secure
    MISCONFIGURED = "misconfigured" # Service reachable but reveals configuration leaks, recursion, or obsolete ciphers


class AuthPrerequisite(str, Enum):
    """Authentication required to access service features or metadata."""

    NONE = "none"
    DEFAULT_CREDENTIALS = "default_credentials"
    DOMAIN_USER = "domain_user"
    KERBEROS_PREAUTH_DISABLED = "kerberos_preauth_disabled"
    ELEVATED_USER = "elevated_user"
    UNKNOWN = "unknown"


class IdentityAttackPathType(str, Enum):
    """Attack path candidate taxonomy for handoff to AD and identity inventory."""

    LDAP_ANONYMOUS_RECONNAISSANCE = "ldap_anonymous_reconnaissance"
    ASREP_ROASTING = "asrep_roasting"
    RPC_ENDPOINT_ENUMERATION = "rpc_endpoint_enumeration"
    SNMP_CREDENTIAL_LEAK = "snmp_credential_leak"
    OPEN_DNS_RECURSION = "open_dns_recursion"
    NTP_MODE6_AMPLIFICATION = "ntp_mode6_amplification"
    NONE = "none"


@dataclass
class IdentityAttackPathCandidate:
    """Actionable candidate path handed off to Active Directory and identity inventory."""

    candidate_id: str
    service_type: str
    target_host: str
    port: int
    vantage: str
    attack_path_type: str
    auth_prerequisites: str
    target_principal: str | None = None
    ad_domain_realm: str | None = None
    applicable_versions: list[str] = field(default_factory=list)
    supporting_evidence: dict[str, Any] = field(default_factory=dict)
    remediation_guidance: str = ""
    evidence_hash: str = ""
    timestamp_utc: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.evidence_hash:
            h = hashlib.sha256(
                f"{self.candidate_id}:{self.target_host}:{self.port}:{self.attack_path_type}:{self.auth_prerequisites}".encode("utf-8")
            ).hexdigest()
            self.evidence_hash = h
        if not self.remediation_guidance:
            guidance_map = {
                IdentityAttackPathType.LDAP_ANONYMOUS_RECONNAISSANCE.value: "Disable LDAP anonymous binds and enforce LDAP signing/channel binding (LDAPS).",
                IdentityAttackPathType.ASREP_ROASTING.value: "Enable Kerberos pre-authentication ('Do not require Kerberos preauthentication' attribute unchecked) for affected account.",
                IdentityAttackPathType.RPC_ENDPOINT_ENUMERATION.value: "Restrict RPC endpoint mapper (port 135) access via host and network firewalls to authorized management segments.",
                IdentityAttackPathType.SNMP_CREDENTIAL_LEAK.value: "Change default SNMP community strings ('public', 'private') or migrate to SNMPv3 with USM authentication and encryption.",
                IdentityAttackPathType.OPEN_DNS_RECURSION.value: "Disable open recursion on DNS resolver or restrict recursion to internal authorized subnets.",
                IdentityAttackPathType.NTP_MODE6_AMPLIFICATION.value: "Disable Mode 6 / monlist queries in NTP configuration ('noquery' restriction).",
            }
            self.remediation_guidance = guidance_map.get(
                self.attack_path_type, "Harden service authentication and network segmentation."
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdentityAttackPathCandidate:
        return cls(
            candidate_id=data["candidate_id"],
            service_type=data["service_type"],
            target_host=data["target_host"],
            port=int(data["port"]),
            vantage=data["vantage"],
            attack_path_type=data["attack_path_type"],
            auth_prerequisites=data.get("auth_prerequisites", AuthPrerequisite.UNKNOWN.value),
            target_principal=data.get("target_principal"),
            ad_domain_realm=data.get("ad_domain_realm"),
            applicable_versions=list(data.get("applicable_versions", [])),
            supporting_evidence=dict(data.get("supporting_evidence", {})),
            remediation_guidance=data.get("remediation_guidance", ""),
            evidence_hash=data.get("evidence_hash", ""),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )


@dataclass
class InfraServiceAssessment:
    """Discrete assessment of an infrastructure or identity-facing service."""

    target_host: str
    resolved_ip: str
    service_type: str
    port: int
    protocol: str = "tcp"
    vantage: str = "external"
    exposure_status: str = ServiceExposureStatus.INACCESSIBLE.value
    canary_validated: bool = False
    canary_identifier: str | None = None
    authentication_required: bool | None = None
    auth_prerequisite: str = AuthPrerequisite.UNKNOWN.value
    applicable_versions: list[str] = field(default_factory=list)
    configuration_details: dict[str, Any] = field(default_factory=dict)
    observed_vulnerabilities: list[str] = field(default_factory=list)
    uncertainty_notes: list[str] = field(default_factory=list)
    attack_path_candidate: IdentityAttackPathCandidate | None = None
    candidates_list: list[IdentityAttackPathCandidate] = field(default_factory=list)
    error_message: str | None = None
    timestamp_utc: str = field(default_factory=utc_now)
    provenance: EvidenceProvenance | None = None

    def __post_init__(self) -> None:
        if self.attack_path_candidate and not self.candidates_list:
            self.candidates_list = [self.attack_path_candidate]
        elif self.candidates_list and not self.attack_path_candidate:
            self.attack_path_candidate = self.candidates_list[0]

    @property
    def protocol_details(self) -> dict[str, Any]:
        return self.configuration_details

    @property
    def attack_path_candidates(self) -> list[IdentityAttackPathCandidate]:
        if self.candidates_list:
            return list(self.candidates_list)
        if self.attack_path_candidate:
            return [self.attack_path_candidate]
        return []

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_host": self.target_host,
            "resolved_ip": self.resolved_ip,
            "service_type": self.service_type,
            "port": self.port,
            "protocol": self.protocol,
            "vantage": self.vantage,
            "exposure_status": self.exposure_status,
            "canary_validated": self.canary_validated,
            "canary_identifier": self.canary_identifier,
            "authentication_required": self.authentication_required,
            "auth_prerequisite": self.auth_prerequisite,
            "applicable_versions": list(self.applicable_versions),
            "configuration_details": dict(self.configuration_details),
            "observed_vulnerabilities": list(self.observed_vulnerabilities),
            "uncertainty_notes": list(self.uncertainty_notes),
            "attack_path_candidate": self.attack_path_candidate.to_dict() if self.attack_path_candidate else None,
            "candidates_list": [c.to_dict() for c in self.candidates_list],
            "error_message": self.error_message,
            "timestamp_utc": self.timestamp_utc,
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InfraServiceAssessment:
        candidate = (
            IdentityAttackPathCandidate.from_dict(data["attack_path_candidate"])
            if data.get("attack_path_candidate")
            else None
        )
        candidates_list = [
            IdentityAttackPathCandidate.from_dict(c)
            for c in data.get("candidates_list", [])
        ]
        if candidate and not candidates_list:
            candidates_list = [candidate]
        prov = (
            EvidenceProvenance.from_dict(data["provenance"])
            if data.get("provenance")
            else None
        )
        return cls(
            target_host=data["target_host"],
            resolved_ip=data["resolved_ip"],
            service_type=data["service_type"],
            port=int(data["port"]),
            protocol=data.get("protocol", "tcp"),
            vantage=data.get("vantage", "external"),
            exposure_status=data.get("exposure_status", ServiceExposureStatus.INACCESSIBLE.value),
            canary_validated=bool(data.get("canary_validated", False)),
            canary_identifier=data.get("canary_identifier"),
            authentication_required=data.get("authentication_required"),
            auth_prerequisite=data.get("auth_prerequisite", AuthPrerequisite.UNKNOWN.value),
            applicable_versions=list(data.get("applicable_versions", [])),
            configuration_details=dict(data.get("configuration_details", {})),
            observed_vulnerabilities=list(data.get("observed_vulnerabilities", [])),
            uncertainty_notes=list(data.get("uncertainty_notes", [])),
            attack_path_candidate=candidate,
            candidates_list=candidates_list,
            error_message=data.get("error_message"),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
            provenance=prov,
        )


@dataclass
class InfraAssessmentReport:
    """Comprehensive evaluation report of infrastructure and identity services."""

    report_id: str
    scope_reference: str
    vantage: str = "external"
    services_assessed: list[InfraServiceAssessment] = field(default_factory=list)
    attack_path_candidates: list[IdentityAttackPathCandidate] = field(default_factory=list)
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
    def total_misconfigured(self) -> int:
        return self.summary.get("misconfigured", 0)

    @property
    def all_attack_path_candidates(self) -> list[IdentityAttackPathCandidate]:
        return list(self.attack_path_candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "scope_reference": self.scope_reference,
            "vantage": self.vantage,
            "services_assessed": [s.to_dict() for s in self.services_assessed],
            "attack_path_candidates": [c.to_dict() for c in self.attack_path_candidates],
            "summary": dict(self.summary),
            "timestamp_utc": self.timestamp_utc,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InfraAssessmentReport:
        return cls(
            report_id=data["report_id"],
            scope_reference=data["scope_reference"],
            vantage=data.get("vantage", "external"),
            services_assessed=[InfraServiceAssessment.from_dict(s) for s in data.get("services_assessed", [])],
            attack_path_candidates=[IdentityAttackPathCandidate.from_dict(c) for c in data.get("attack_path_candidates", [])],
            summary=dict(data.get("summary", {})),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(canonical(self.to_dict()) + b"\n")
