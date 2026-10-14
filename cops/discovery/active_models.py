"""Data models and contracts for bounded active discovery, service identification, and resumable scans."""

from __future__ import annotations

import os
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cops.evidence.canonical import canonical, decode_json, utc_now

from .models import EvidenceProvenance

# A complete TCP sweep can exceed the evidence module's smaller default limit.
# Keep checkpoint reads and writes bounded to the same explicit ceiling.
MAX_ACTIVE_CHECKPOINT_BYTES = 256 * 1024 * 1024


class ScanVantage(str, Enum):
    """Network vantage point from which active assessment probes originate."""

    EXTERNAL = "external"
    INTERNAL = "internal"
    EGRESS_POINT = "egress_point"
    CLOUD_TENANT = "cloud_tenant"


class Protocol(str, Enum):
    """Transport protocol evaluated during active assessment."""

    TCP = "tcp"
    UDP = "udp"


class PortState(str, Enum):
    """Port state confirmed by active probe response."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNREACHABLE = "unreachable"
    TIMED_OUT = "timed_out"
    UNKNOWN = "unknown"


class ServiceReachability(str, Enum):
    """Reconciliation of reachability from probe vantage."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    FILTERED = "filtered"
    INTERMITTENT = "intermittent"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Confidence calibration for inferred service fingerprints."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"
    PROVISIONAL = "provisional"


@dataclass
class ObservedTLS:
    """Directly observed TLS protocol and certificate parameters."""

    version: str | None = None
    cipher_suite: str | None = None
    subject_cn: str | None = None
    subject_dn: str | None = None
    issuer_dn: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    sans: list[str] = field(default_factory=list)
    alpn_protocols: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ObservedTLS:
        return cls(
            version=data.get("version"),
            cipher_suite=data.get("cipher_suite"),
            subject_cn=data.get("subject_cn"),
            subject_dn=data.get("subject_dn"),
            issuer_dn=data.get("issuer_dn"),
            valid_from=data.get("valid_from"),
            valid_until=data.get("valid_until"),
            sans=list(data.get("sans", [])),
            alpn_protocols=list(data.get("alpn_protocols", [])),
        )


@dataclass
class ObservedConfiguration:
    """Verbatim configuration and responses observed during active assessment."""

    raw_banner: str | None = None
    banner_bytes: str | None = None
    http_status: int | None = None
    http_headers: dict[str, str] = field(default_factory=dict)
    tls: ObservedTLS | None = None
    protocol_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "raw_banner": self.raw_banner,
            "banner_bytes": self.banner_bytes,
            "http_status": self.http_status,
            "http_headers": dict(self.http_headers),
            "tls": self.tls.to_dict() if self.tls else None,
            "protocol_metadata": dict(self.protocol_metadata),
        }
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ObservedConfiguration:
        tls_data = data.get("tls")
        return cls(
            raw_banner=data.get("raw_banner"),
            banner_bytes=data.get("banner_bytes"),
            http_status=data.get("http_status"),
            http_headers=dict(data.get("http_headers", {})),
            tls=ObservedTLS.from_dict(tls_data) if tls_data else None,
            protocol_metadata=dict(data.get("protocol_metadata", {})),
        )


@dataclass
class InferredFingerprint:
    """Service and product inferences derived from observed configuration, with visible uncertainty."""

    service_name: str
    product: str | None = None
    version: str | None = None
    os_inferred: str | None = None
    confidence: str = ConfidenceLevel.MEDIUM.value
    uncertainty_reasons: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InferredFingerprint:
        return cls(
            service_name=data["service_name"],
            product=data.get("product"),
            version=data.get("version"),
            os_inferred=data.get("os_inferred"),
            confidence=data.get("confidence", ConfidenceLevel.MEDIUM.value),
            uncertainty_reasons=list(data.get("uncertainty_reasons", [])),
            evidence_sources=list(data.get("evidence_sources", [])),
        )


@dataclass
class ActiveServiceAssessment:
    """Discrete assessment result for an approved host, port, protocol, and vantage."""

    probe_id: str
    target_host: str
    resolved_ip: str
    port: int
    protocol: str = Protocol.TCP.value
    vantage: str = ScanVantage.EXTERNAL.value
    port_state: str = PortState.OPEN.value
    reachability: str = ServiceReachability.REACHABLE.value
    observed_config: ObservedConfiguration = field(default_factory=ObservedConfiguration)
    inferred_fingerprint: InferredFingerprint | None = None
    latency_ms: float | None = None
    timestamp_utc: str = field(default_factory=utc_now)
    error_message: str | None = None
    provenance: EvidenceProvenance | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "target_host": self.target_host,
            "resolved_ip": self.resolved_ip,
            "port": self.port,
            "protocol": self.protocol,
            "vantage": self.vantage,
            "port_state": self.port_state,
            "reachability": self.reachability,
            "observed_config": self.observed_config.to_dict(),
            "inferred_fingerprint": self.inferred_fingerprint.to_dict() if self.inferred_fingerprint else None,
            "latency_ms": self.latency_ms,
            "timestamp_utc": self.timestamp_utc,
            "error_message": self.error_message,
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActiveServiceAssessment:
        prov = EvidenceProvenance.from_dict(data["provenance"]) if data.get("provenance") else None
        fingerprint = (
            InferredFingerprint.from_dict(data["inferred_fingerprint"]) if data.get("inferred_fingerprint") else None
        )
        return cls(
            probe_id=data["probe_id"],
            target_host=data["target_host"],
            resolved_ip=data["resolved_ip"],
            port=data["port"],
            protocol=data.get("protocol", Protocol.TCP.value),
            vantage=data.get("vantage", ScanVantage.EXTERNAL.value),
            port_state=data.get("port_state", PortState.OPEN.value),
            reachability=data.get("reachability", ServiceReachability.REACHABLE.value),
            observed_config=ObservedConfiguration.from_dict(data.get("observed_config", {})),
            inferred_fingerprint=fingerprint,
            latency_ms=data.get("latency_ms"),
            timestamp_utc=data.get("timestamp_utc", utc_now()),
            error_message=data.get("error_message"),
            provenance=prov,
        )


@dataclass
class ScanBudget:
    """Operational budgets and rate limits constraining active execution."""

    timeout_seconds: float = 2.0
    max_total_seconds: float | None = None
    max_retries: int = 1
    rate_limit_pps: float = 10.0
    max_targets: int | None = None
    max_probes: int | None = 1024

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanBudget:
        def number(name: str, default: float | None) -> float | None:
            value = data.get(name, default)
            if value is None and default is None:
                return None
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a number")
            return float(value)

        def integer(name: str, default: int | None) -> int | None:
            value = data.get(name, default)
            if value is None and default is None:
                return None
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            return value

        return cls(
            timeout_seconds=number("timeout_seconds", 2.0),
            max_total_seconds=number("max_total_seconds", None),
            max_retries=integer("max_retries", 1),
            rate_limit_pps=number("rate_limit_pps", 10.0),
            max_targets=integer("max_targets", None),
            max_probes=integer("max_probes", 1024),
        )


@dataclass
class TargetShiftQuarantine:
    """Record of target that shifted resolution outside approved boundaries during scan."""

    target_host: str
    original_ip: str | None
    new_ip: str
    reason: str
    timestamp_utc: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetShiftQuarantine:
        return cls(
            target_host=data["target_host"],
            original_ip=data.get("original_ip"),
            new_ip=data["new_ip"],
            reason=data["reason"],
            timestamp_utc=data.get("timestamp_utc", utc_now()),
        )


@dataclass
class ActiveScanSession:
    """Resumable active scanning session with idempotent side-effect tracking."""

    session_id: str
    scope_reference: str
    approved_targets: list[str]
    approved_ports: list[int]
    approved_udp_ports: list[int] = field(default_factory=list)
    udp_dns_probe_ports: list[int] = field(default_factory=list)
    vantage: str = ScanVantage.EXTERNAL.value
    budget: ScanBudget = field(default_factory=ScanBudget)
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    status: str = "in_progress"  # in_progress, completed, budget_exhausted, requires_reconciliation
    completed_probe_keys: set[str] = field(default_factory=set)
    pending_probe_keys: set[str] = field(default_factory=set)
    assessments: list[ActiveServiceAssessment] = field(default_factory=list)
    quarantined_targets: list[TargetShiftQuarantine] = field(default_factory=list)
    total_probes_dispatched: int = 0
    total_side_effects: int = 0
    elapsed_seconds: float = 0.0
    bound_plan_sha256: str | None = None

    @staticmethod
    def make_probe_key(vantage: str, protocol: str, host: str, port: int) -> str:
        """Deterministic unique key for a probe target/port."""
        return f"{vantage}:{protocol.lower()}:{host.lower()}:{port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "scope_reference": self.scope_reference,
            "approved_targets": list(self.approved_targets),
            "approved_ports": list(self.approved_ports),
            "approved_udp_ports": list(self.approved_udp_ports),
            "udp_dns_probe_ports": list(self.udp_dns_probe_ports),
            "vantage": self.vantage,
            "budget": self.budget.to_dict(),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "completed_probe_keys": sorted(self.completed_probe_keys),
            "pending_probe_keys": sorted(self.pending_probe_keys),
            "assessments": [a.to_dict() for a in self.assessments],
            "quarantined_targets": [q.to_dict() for q in self.quarantined_targets],
            "total_probes_dispatched": self.total_probes_dispatched,
            "total_side_effects": self.total_side_effects,
            "elapsed_seconds": self.elapsed_seconds,
            "bound_plan_sha256": self.bound_plan_sha256,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActiveScanSession:
        session = cls(
            session_id=data["session_id"],
            scope_reference=data["scope_reference"],
            approved_targets=list(data["approved_targets"]),
            approved_ports=list(data["approved_ports"]),
            approved_udp_ports=list(data.get("approved_udp_ports", [])),
            udp_dns_probe_ports=list(data.get("udp_dns_probe_ports", [])),
            vantage=data.get("vantage", ScanVantage.EXTERNAL.value),
            budget=ScanBudget.from_dict(data.get("budget", {})),
            started_at=data.get("started_at", utc_now()),
            completed_at=data.get("completed_at"),
            status=data.get("status", "in_progress"),
            completed_probe_keys=set(data.get("completed_probe_keys", [])),
            pending_probe_keys=set(data.get("pending_probe_keys", [])),
            assessments=[ActiveServiceAssessment.from_dict(a) for a in data.get("assessments", [])],
            quarantined_targets=[TargetShiftQuarantine.from_dict(q) for q in data.get("quarantined_targets", [])],
            total_probes_dispatched=data.get("total_probes_dispatched", 0),
            total_side_effects=data.get("total_side_effects", 0),
            elapsed_seconds=data.get("elapsed_seconds", 0.0),
            bound_plan_sha256=data.get("bound_plan_sha256"),
        )
        return session

    def save_checkpoint(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=p.parent, prefix=f".{p.name}.", delete=False) as stream:
                temporary = stream.name
                stream.write(canonical(self.to_dict(), max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES - 1) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, p)
            temporary = None
            if os.name != "nt":
                directory_fd = os.open(p.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if temporary is not None:
                os.unlink(temporary)

    @classmethod
    def load_checkpoint(cls, path: Path | str) -> ActiveScanSession:
        p = Path(path)
        with p.open("rb") as stream:
            raw = stream.read(MAX_ACTIVE_CHECKPOINT_BYTES + 1)
        if len(raw) > MAX_ACTIVE_CHECKPOINT_BYTES:
            raise ValueError("Active scan checkpoint exceeds the size limit")
        data = decode_json(raw, max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES)
        return cls.from_dict(data)


@dataclass
class ScanDelta:
    """Comparison delta verifying remediated exposure between baseline and current scans."""

    baseline_session_id: str
    current_session_id: str
    remediated_exposures: list[dict[str, Any]]
    new_exposures: list[dict[str, Any]]
    persistent_exposures: list[dict[str, Any]]
    fingerprint_changes: list[dict[str, Any]]
    remediation_rate: float
    unverified_exposures: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
