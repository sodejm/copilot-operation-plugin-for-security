"""Data models and contracts for bounded active discovery, service identification, and resumable scans."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import stat
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
ACTIVE_CHECKPOINT_JOURNAL_VERSION = 1


def canonical_target_identity(host: str) -> str:
    """Return one comparison and ledger identity for a hostname or IP literal."""
    normalized = host.lower()
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        return normalized


def expand_target_specs(target_specs: list[str], *, max_targets: int) -> list[str]:
    """Expand explicit host/IP/CIDR specs into bounded canonical targets."""
    if isinstance(max_targets, bool) or not isinstance(max_targets, int) or max_targets <= 0:
        raise ValueError("max_targets must be a positive integer")
    expanded: list[str] = []
    seen: set[str] = set()
    for raw_spec in target_specs:
        if not isinstance(raw_spec, str) or not raw_spec.strip():
            raise ValueError("Target specifications must be nonempty strings")
        spec = raw_spec.strip()
        if "/" in spec:
            try:
                network = ipaddress.ip_network(spec, strict=False)
            except ValueError as error:
                raise ValueError(f"Invalid target CIDR: {spec}") from error
            if network.num_addresses > max_targets - len(expanded):
                raise ValueError(f"Target expansion exceeds max_targets={max_targets}")
            candidates = (str(address) for address in network)
        else:
            candidates = (canonical_target_identity(spec),)
        for candidate in candidates:
            if candidate in seen:
                raise ValueError(f"Target specifications overlap or duplicate {candidate}")
            seen.add(candidate)
            expanded.append(candidate)
            if len(expanded) > max_targets:
                raise ValueError(f"Target expansion exceeds max_targets={max_targets}")
    return expanded


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
    max_concurrency: int = 1

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
            max_concurrency=integer("max_concurrency", 1),
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
    status: str = "in_progress"  # in_progress, completed, cancelled, budget_exhausted, requires_reconciliation
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
        return f"{vantage}:{protocol.lower()}:{canonical_target_identity(host)}:{port}"

    def coverage_summary(self) -> dict[str, Any]:
        """Summarize durable attempted, skipped, and outstanding plan coverage."""
        planned = {
            self.make_probe_key(self.vantage, protocol, target, port)
            for target in self.approved_targets
            for protocol, ports in (
                (Protocol.TCP.value, self.approved_ports),
                (Protocol.UDP.value, self.approved_udp_ports),
            )
            for port in ports
        }
        attempted = self.completed_probe_keys | self.pending_probe_keys
        quarantined_hosts = {canonical_target_identity(item.target_host) for item in self.quarantined_targets}
        quarantined = {
            key
            for key in planned - attempted
            if any(
                key.startswith(f"{self.vantage}:{protocol}:{host}:")
                for host in quarantined_hosts
                for protocol in (Protocol.TCP.value, Protocol.UDP.value)
            )
        }
        port_states: dict[str, int] = {}
        timed_out = 0
        for assessment in self.assessments:
            port_states[assessment.port_state] = port_states.get(assessment.port_state, 0) + 1
            error = (assessment.error_message or "").lower()
            if assessment.port_state == PortState.TIMED_OUT.value or "timed out" in error:
                timed_out += 1
        return {
            "planned": len(planned),
            "attempted": len(attempted),
            "completed": len(self.completed_probe_keys),
            "pending_reconciliation": len(self.pending_probe_keys),
            "skipped": {"total": len(quarantined), "quarantined": len(quarantined)},
            "unassessed": len(planned - attempted - quarantined),
            "port_states": dict(sorted(port_states.items())),
            "timed_out": timed_out,
        }

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
            "coverage": self.coverage_summary(),
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
        """Atomically compact the complete session and retire its probe journal."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical(self.to_dict(), max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES - 1) + b"\n"
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=p.parent, prefix=f".{p.name}.", delete=False) as stream:
                temporary = stream.name
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if self._checkpoint_journal_exists(p):
                # Bind the existing journal to the replacement snapshot before
                # the atomic swap. After a crash, the loader either replays the
                # old base or resumes after this marker on the new base.
                self._append_checkpoint_event(
                    p,
                    {
                        "event": "compact",
                        "checkpoint_sha256": payload_sha256,
                        "elapsed_seconds": self.elapsed_seconds,
                    },
                    durable=True,
                )
            os.replace(temporary, p)
            temporary = None
            if os.name != "nt":
                directory_fd = os.open(p.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            if self._remove_checkpoint_journal(p):
                if os.name != "nt":
                    directory_fd = os.open(p.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
        finally:
            if temporary is not None:
                os.unlink(temporary)

    @staticmethod
    def checkpoint_journal_path(path: Path | str) -> Path:
        """Return the sidecar used for constant-time durable probe events."""
        p = Path(path)
        return p.with_name(f"{p.name}.journal")

    @staticmethod
    def _journal_open_flags(flags: int) -> int:
        return flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    @staticmethod
    def _validate_journal_descriptor(descriptor: int) -> os.stat_result:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Active scan checkpoint journal must be a regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("Active scan checkpoint journal must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("Active scan checkpoint journal permissions must be private")
        if metadata.st_nlink != 1:
            raise ValueError("Active scan checkpoint journal must not have hard links")
        return metadata

    @staticmethod
    def _open_checkpoint_directory(path: Path) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return os.open(path.parent, flags)

    @classmethod
    def _checkpoint_journal_exists(cls, path: Path) -> bool:
        directory = cls._open_checkpoint_directory(path)
        try:
            try:
                os.stat(cls.checkpoint_journal_path(path).name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return False
            return True
        finally:
            os.close(directory)

    @classmethod
    def _open_checkpoint_journal(cls, path: Path, flags: int) -> int:
        directory = cls._open_checkpoint_directory(path)
        try:
            try:
                descriptor = os.open(
                    cls.checkpoint_journal_path(path).name,
                    cls._journal_open_flags(flags),
                    dir_fd=directory,
                )
            except OSError as error:
                raise ValueError("Active scan checkpoint journal is unavailable or unsafe") from error
        finally:
            os.close(directory)
        try:
            cls._validate_journal_descriptor(descriptor)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @classmethod
    def _remove_checkpoint_journal(cls, path: Path) -> bool:
        directory = cls._open_checkpoint_directory(path)
        name = cls.checkpoint_journal_path(path).name
        try:
            try:
                descriptor = os.open(name, cls._journal_open_flags(os.O_RDONLY), dir_fd=directory)
            except FileNotFoundError:
                return False
            except OSError as error:
                raise ValueError("Active scan checkpoint journal is unavailable or unsafe") from error
            try:
                opened = cls._validate_journal_descriptor(descriptor)
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                    raise ValueError("Active scan checkpoint journal changed during cleanup")
                os.unlink(name, dir_fd=directory)
            finally:
                os.close(descriptor)
            return True
        finally:
            os.close(directory)

    def _ensure_checkpoint_journal(self, path: Path | str) -> Path:
        p = Path(path)
        journal = self.checkpoint_journal_path(p)
        raw_checkpoint = p.read_bytes()
        header = {
            "event": "header",
            "version": ACTIVE_CHECKPOINT_JOURNAL_VERSION,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "bound_plan_sha256": self.bound_plan_sha256,
            "base_sha256": hashlib.sha256(raw_checkpoint).hexdigest(),
        }
        directory = self._open_checkpoint_directory(p)
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    journal.name,
                    self._journal_open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                    0o600,
                    dir_fd=directory,
                )
            except FileExistsError:
                existing = self._open_checkpoint_journal(p, os.O_RDONLY)
                os.close(existing)
                return journal
            self._validate_journal_descriptor(descriptor)
            record = canonical(header, max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES - 1) + b"\n"
            view = memoryview(record)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Could not initialize active scan checkpoint journal")
                view = view[written:]
            os.fsync(descriptor)
            if os.name != "nt":
                os.fsync(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)
        return journal

    def _append_checkpoint_event(
        self,
        path: Path | str,
        event: dict[str, Any],
        *,
        durable: bool,
    ) -> None:
        journal = self._ensure_checkpoint_journal(path)
        record = canonical(event, max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES - 1) + b"\n"
        checkpoint_size = Path(path).stat().st_size
        descriptor = self._open_checkpoint_journal(Path(path), os.O_WRONLY | os.O_APPEND)
        try:
            journal_size = os.fstat(descriptor).st_size
            if checkpoint_size + journal_size + len(record) > MAX_ACTIVE_CHECKPOINT_BYTES:
                raise ValueError("Active scan checkpoint and journal exceed the size limit")
            view = memoryview(record)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Could not append active scan checkpoint event")
                view = view[written:]
            if durable:
                os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def append_probe_reservation(self, path: Path | str, probe_key: str) -> None:
        """Durably record one reservation before its network side effect."""
        self.append_probe_reservations(path, [probe_key])

    def append_probe_reservations(self, path: Path | str, probe_keys: list[str]) -> None:
        """Durably reserve a bounded batch before any included side effect."""
        if not probe_keys or any(not isinstance(key, str) or not key for key in probe_keys):
            raise ValueError("Probe reservation batch must contain nonempty keys")
        if len(set(probe_keys)) != len(probe_keys):
            raise ValueError("Probe reservation batch contains duplicate keys")
        self._append_checkpoint_event(
            path,
            {
                "event": "reserve_batch",
                "probe_keys": probe_keys,
                "elapsed_seconds": self.elapsed_seconds,
            },
            durable=True,
        )

    def append_probe_completion(
        self,
        path: Path | str,
        probe_key: str,
        assessment: ActiveServiceAssessment,
    ) -> None:
        """Journal one result; the durable reservation preserves crash safety."""
        self._append_checkpoint_event(
            path,
            {
                "event": "complete",
                "probe_key": probe_key,
                "elapsed_seconds": self.elapsed_seconds,
                "assessment": assessment.to_dict(),
            },
            durable=False,
        )

    def append_probe_release(self, path: Path | str, probe_keys: list[str]) -> None:
        """Durably release reservations that were batched but not dispatched."""
        if not probe_keys or any(not isinstance(key, str) or not key for key in probe_keys):
            raise ValueError("Probe release batch must contain nonempty keys")
        if len(set(probe_keys)) != len(probe_keys):
            raise ValueError("Probe release batch contains duplicate keys")
        self._append_checkpoint_event(
            path,
            {
                "event": "release_batch",
                "probe_keys": probe_keys,
                "elapsed_seconds": self.elapsed_seconds,
            },
            durable=True,
        )

    @classmethod
    def load_checkpoint(cls, path: Path | str) -> ActiveScanSession:
        p = Path(path)
        with p.open("rb") as stream:
            raw = stream.read(MAX_ACTIVE_CHECKPOINT_BYTES + 1)
        if len(raw) > MAX_ACTIVE_CHECKPOINT_BYTES:
            raise ValueError("Active scan checkpoint exceeds the size limit")
        data = decode_json(raw, max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES)
        session = cls.from_dict(data)
        journal = cls.checkpoint_journal_path(p)
        if not cls._checkpoint_journal_exists(p):
            return session
        descriptor = cls._open_checkpoint_journal(p, os.O_RDONLY)
        try:
            journal_size = os.fstat(descriptor).st_size
            if len(raw) + journal_size > MAX_ACTIVE_CHECKPOINT_BYTES:
                raise ValueError("Active scan checkpoint and journal exceed the size limit")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                lines = stream.readlines()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not lines or not lines[0].endswith(b"\n"):
            raise ValueError("Active scan checkpoint journal is incomplete")
        # A crash can truncate the last nondurable completion. Its reservation
        # remains durable, so ignoring only that final fragment is conservative.
        if not lines[-1].endswith(b"\n"):
            lines = lines[:-1]
        header = decode_json(lines[0], max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES)
        if (
            header.get("event") != "header"
            or header.get("version") != ACTIVE_CHECKPOINT_JOURNAL_VERSION
            or header.get("session_id") != session.session_id
            or header.get("started_at") != session.started_at
            or header.get("bound_plan_sha256") != session.bound_plan_sha256
        ):
            raise ValueError("Active scan checkpoint journal binding is invalid")
        current_sha256 = hashlib.sha256(raw).hexdigest()
        first_event_index = 1
        if header.get("base_sha256") != current_sha256:
            compact_indexes: list[int] = []
            for index, raw_event in enumerate(lines[1:], start=1):
                event = decode_json(raw_event, max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES)
                if event.get("event") == "compact" and event.get("checkpoint_sha256") == current_sha256:
                    compact_indexes.append(index)
            if not compact_indexes:
                raise ValueError("Active scan checkpoint journal does not match its compacted checkpoint")
            first_event_index = compact_indexes[-1] + 1
        for raw_event in lines[first_event_index:]:
            event = decode_json(raw_event, max_bytes=MAX_ACTIVE_CHECKPOINT_BYTES)
            elapsed = event.get("elapsed_seconds")
            if not isinstance(elapsed, (int, float)) or elapsed < 0:
                raise ValueError("Active scan checkpoint journal elapsed time is invalid")
            session.elapsed_seconds = max(session.elapsed_seconds, float(elapsed))
            if event.get("event") == "compact":
                digest = event.get("checkpoint_sha256")
                if not isinstance(digest, str) or len(digest) != 64:
                    raise ValueError("Active scan checkpoint journal compact marker is invalid")
                continue
            if event.get("event") in {"reserve", "reserve_batch"}:
                probe_keys = event.get("probe_keys", [event.get("probe_key")])
                if (
                    not isinstance(probe_keys, list)
                    or not probe_keys
                    or any(not isinstance(key, str) or not key for key in probe_keys)
                    or len(set(probe_keys)) != len(probe_keys)
                ):
                    raise ValueError("Active scan checkpoint journal probe keys are invalid")
                if any(
                    key in session.pending_probe_keys or key in session.completed_probe_keys
                    for key in probe_keys
                ):
                    raise ValueError("Active scan checkpoint journal contains a duplicate reservation")
                session.pending_probe_keys.update(probe_keys)
                session.total_probes_dispatched += len(probe_keys)
                continue
            if event.get("event") == "release_batch":
                probe_keys = event.get("probe_keys")
                if (
                    not isinstance(probe_keys, list)
                    or not probe_keys
                    or any(not isinstance(key, str) or not key for key in probe_keys)
                    or len(set(probe_keys)) != len(probe_keys)
                    or any(key not in session.pending_probe_keys for key in probe_keys)
                ):
                    raise ValueError("Active scan checkpoint journal release is invalid")
                session.pending_probe_keys.difference_update(probe_keys)
                session.total_probes_dispatched -= len(probe_keys)
                if session.total_probes_dispatched < 0:
                    raise ValueError("Active scan checkpoint journal probe count is invalid")
                continue
            probe_key = event.get("probe_key")
            if not isinstance(probe_key, str):
                raise ValueError("Active scan checkpoint journal probe key is invalid")
            if event.get("event") != "complete" or probe_key not in session.pending_probe_keys:
                raise ValueError("Active scan checkpoint journal event order is invalid")
            assessment_data = event.get("assessment")
            if not isinstance(assessment_data, dict):
                raise ValueError("Active scan checkpoint journal assessment is invalid")
            assessment = ActiveServiceAssessment.from_dict(assessment_data)
            assessment_key = cls.make_probe_key(
                assessment.vantage,
                assessment.protocol,
                assessment.target_host,
                assessment.port,
            )
            if assessment_key != probe_key:
                raise ValueError("Active scan checkpoint journal assessment identity is invalid")
            session.pending_probe_keys.remove(probe_key)
            session.completed_probe_keys.add(probe_key)
            session.assessments.append(assessment)
            session.total_side_effects += 1
        return session


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
