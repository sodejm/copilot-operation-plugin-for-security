"""Offline, evidence-gated handoff from discovery to service validation.

This module neither probes a service nor creates an execution authorization. The
coordinator must bind any proposed action to an approved engagement and budget.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Collection, Mapping
from dataclasses import asdict, dataclass, replace
from hmac import compare_digest

from cops.evidence.canonical import EvidenceError, digest, timestamp
from cops.routing.catalog import SpecialistCatalogError, get_specialist

from .active_models import ActiveScanSession, ActiveServiceAssessment, ObservedConfiguration, active_assessment_digest
from .models import EvidenceProvenance

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_VANTAGES = frozenset({"external", "internal", "egress_point", "cloud_tenant"})
_TRANSPORTS = frozenset({"tcp", "udp"})
_SPECIALIST_ID = "cops-pentest-specialist"
_SESSION_STATUSES = frozenset({"in_progress", "completed", "budget_exhausted", "interrupted"})
_PLAN_VERSION = "cops.service-validation-plan/v2"


def _canonical_host(host: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip() or len(host) > 253:
        raise ValueError("endpoint host must be an exact hostname or IP literal")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        canonical_host = host.lower()
        if any(not _LABEL.fullmatch(part) for part in canonical_host.split(".")):
            raise ValueError("endpoint host must be an exact hostname or IP literal") from None
        return canonical_host


@dataclass(frozen=True)
class ApprovedEndpoint:
    """Exact endpoint selected from a separately validated engagement scope."""

    host: str
    resolved_ip: str
    port: int
    transport: str
    vantage: str

    def __post_init__(self) -> None:
        canonical_host = _canonical_host(self.host)
        try:
            canonical_ip = str(ipaddress.ip_address(self.resolved_ip))
        except ValueError as err:
            raise ValueError("endpoint resolved_ip must be an IP literal") from err
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")
        if self.transport not in _TRANSPORTS or self.vantage not in _VANTAGES:
            raise ValueError("endpoint transport or vantage is unsupported")
        object.__setattr__(self, "host", canonical_host)
        object.__setattr__(self, "resolved_ip", canonical_ip)


@dataclass(frozen=True)
class ServiceValidationPlan:
    """Auditable proposal; a worker must recheck every prerequisite before use."""

    plan_id: str
    endpoint: ApprovedEndpoint
    service: str
    specialist: str
    skill_id: str
    session_id: str
    scope_reference: str
    probe_key: str
    evidence_probe_id: str
    evidence_sha256: str
    action: str
    prerequisites: tuple[str, ...]
    expected_proof: str
    rollback: str
    stop_conditions: tuple[str, ...]
    requires_execution_authorization: bool = True
    requires_budget: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def service_validation_plan_digest(plan: ServiceValidationPlan) -> str:
    """Bind every executable plan field to its stable identifier."""
    if not isinstance(plan, ServiceValidationPlan):
        raise ValueError("service validation plan is malformed")
    payload = asdict(plan)
    payload.pop("plan_id")
    payload["prerequisites"] = list(plan.prerequisites)
    payload["stop_conditions"] = list(plan.stop_conditions)
    return digest({"version": _PLAN_VERSION, "plan": payload})


def service_validation_plan_is_intact(plan: ServiceValidationPlan) -> bool:
    """Return whether a plan still matches the complete approved proposal."""
    try:
        return compare_digest(plan.plan_id, service_validation_plan_digest(plan))
    except (AttributeError, TypeError, ValueError):
        return False


@dataclass(frozen=True)
class ServiceEntryHandoff:
    """Explicitly separates exposure and candidates from validated outcomes."""

    status: str
    endpoint: ApprovedEndpoint | None
    observed_exposure: bool
    service: str | None
    specialist: str | None
    evidence_probe_id: str
    reason: str
    next_action: str
    skill_id: str | None = None
    plan: ServiceValidationPlan | None = None
    verified_finding: None = None
    authorized_use: None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _observed_services(observation: ObservedConfiguration) -> set[tuple[str, str, str]]:
    """Use response evidence only; fingerprints and well-known ports are hints."""
    services: set[tuple[str, str, str]] = set()
    banner = observation.raw_banner if isinstance(observation.raw_banner, str) else ""
    banner = banner[:512]
    binary_banner = b""
    if isinstance(observation.banner_bytes, str):
        try:
            binary_banner = bytes.fromhex(observation.banner_bytes)
        except ValueError:
            binary_banner = b""
    if banner.startswith("SSH-"):
        services.add(("ssh", "network-remote-and-file-services", "SSH configuration and authentication boundaries"))
    if re.match(r"^220[^\r\n]{0,200}\b(?:FTP|vsftpd|ProFTPD|Pure-FTPd)\b", banner, re.I):
        services.add(("ftp", "network-remote-and-file-services", "FTP authentication and transfer boundaries"))
    if re.match(r"^220[^\r\n]{0,200}\b(?:SMTP|ESMTP|Postfix|Exim)\b", banner, re.I):
        services.add(("smtp", "network-messaging-services", "SMTP relay and authentication boundaries"))
    if re.match(r"^\* OK[^\r\n]{0,200}\bIMAP\b", banner, re.I):
        services.add(("imap", "network-messaging-services", "IMAP authentication and access boundaries"))
    if re.match(r"^\+OK[^\r\n]{0,200}\bPOP3\b", banner, re.I):
        services.add(("pop3", "network-messaging-services", "POP3 authentication and access boundaries"))
    if re.match(r"^-ERR[^\r\n]{0,200}\bRedis\b", banner, re.I):
        services.add(("redis", "network-data-services", "Redis configuration and access boundaries"))
    if banner in {"+PONG", "+PONG\r\n"} or re.match(r"^-NOAUTH\b", banner, re.I):
        services.add(("redis", "network-data-services", "Redis configuration and access boundaries"))
    docker_response = bool(
        re.match(r'^\s*\{[^\r\n]{0,400}"ApiVersion"\s*:', banner)
        or re.search(r'\r\n\r\n\s*\{[^\r\n]{0,400}"ApiVersion"\s*:', banner)
    )
    if docker_response:
        services.add(("docker-api", "network-developer-interfaces", "Docker API access and trust boundaries"))
    dns_response = (
        len(binary_banner) >= 14
        and int.from_bytes(binary_banner[:2], "big") == len(binary_banner) - 2
        and bool(binary_banner[4] & 0x80)
    )
    if re.match(r"^DNS response\b", banner, re.I) or dns_response:
        services.add(("dns", "network-infrastructure-services", "DNS recursion and authority boundaries"))
    if re.match(r"^SOCKS(?:4|5)?\b", banner, re.I) or binary_banner == b"\x05\x00":
        services.add(("socks", "network-legacy-and-proxy-services", "SOCKS proxy access and egress boundaries"))
    if not docker_response and (
        (type(observation.http_status) is int and 100 <= observation.http_status <= 599)
        or re.match(r"^HTTP/\d(?:\.\d)? [1-5]\d\d\b", banner)
    ):
        services.add(("http", "web-api-inventory-and-replay", "HTTP exposure and authentication boundaries"))
    return services


def _prepare_service_entry_handoff(
    assessment: ActiveServiceAssessment,
    *,
    session: ActiveScanSession,
    approved_endpoints: Collection[ApprovedEndpoint],
    quarantined_hosts: Collection[str],
    session_targets: Collection[str],
    session_valid: bool,
    supported_skills: Collection[str],
    assessment_probe_key_counts: Mapping[str, int],
) -> ServiceEntryHandoff:
    """Prepare one non-executing candidate from a verified scan checkpoint.

    This private helper can only be reached through the session wrapper, which
    supplies trusted scope and the checkpoint's quarantine and route catalog.
    """
    probe_id = assessment.probe_id if isinstance(assessment.probe_id, str) else ""
    try:
        endpoint = ApprovedEndpoint(
            assessment.target_host,
            assessment.resolved_ip,
            assessment.port,
            assessment.protocol,
            assessment.vantage,
        )
    except ValueError:
        return ServiceEntryHandoff(
            "blocked_scope",
            None,
            False,
            None,
            None,
            probe_id,
            "Discovery endpoint is malformed",
            "Repair the discovery evidence and revalidate engagement scope",
        )
    if endpoint not in approved_endpoints:
        return ServiceEntryHandoff(
            "blocked_scope",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Exact endpoint is outside the approved set",
            "Update and approve scope before any follow-on action",
        )
    if endpoint.host in quarantined_hosts:
        return ServiceEntryHandoff(
            "blocked_scope",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "The host was quarantined after an identity or resolution change",
            "Resolve the quarantine against trusted scope before any follow-on action",
        )
    try:
        if not probe_id or probe_id != probe_id.strip() or len(probe_id) > 128:
            raise EvidenceError("invalid_probe_id")
        timestamp(assessment.timestamp_utc)
    except EvidenceError:
        return ServiceEntryHandoff(
            "invalid_evidence",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Discovery evidence has no valid probe identity or timestamp",
            "Repair or repeat discovery within approved scope",
        )
    if not session_valid:
        return ServiceEntryHandoff(
            "invalid_session",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Scan checkpoint has invalid session identity, scope reference, vantage, status, or target list",
            "Reconcile the scan checkpoint before routing",
        )
    probe_key = ActiveScanSession.make_probe_key(
        assessment.vantage, assessment.protocol, assessment.target_host, assessment.port
    )
    if assessment_probe_key_counts.get(probe_key, 0) != 1:
        return ServiceEntryHandoff(
            "invalid_session",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Scan checkpoint has multiple assessment records for this completed probe",
            "Reconcile the scan checkpoint before routing",
        )
    if (
        endpoint.host not in session_targets
        or endpoint.port not in session.approved_ports
        or endpoint.vantage != session.vantage
        or probe_key not in session.completed_probe_keys
    ):
        return ServiceEntryHandoff(
            "invalid_session",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Assessment is not a completed probe in this scan session",
            "Reconcile the checkpoint side-effect ledger before routing",
        )
    provenance = assessment.provenance
    try:
        evidence_sha256 = active_assessment_digest(assessment)
    except (EvidenceError, AttributeError, TypeError, ValueError):
        return ServiceEntryHandoff(
            "invalid_evidence",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Assessment cannot be bound to a bounded evidence digest",
            "Repair or repeat discovery within approved scope",
        )
    if not isinstance(provenance, EvidenceProvenance) or provenance.source_type != "active_scan":
        return ServiceEntryHandoff(
            "unverified_source",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Assessment has no native active-scan provenance; imported evidence needs revalidation",
            "Revalidate the imported observation within approved scope",
        )
    if (
        provenance.source_id != session.session_id
        or provenance.path_or_uri != session.scope_reference
        or provenance.raw_record_ref != probe_key
        or provenance.timestamp != assessment.timestamp_utc
        or provenance.sha256 != evidence_sha256
    ):
        return ServiceEntryHandoff(
            "invalid_evidence",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "Assessment provenance does not match the scan session, probe, or recorded evidence",
            "Reconcile the checkpoint before routing",
        )
    if assessment.port_state != "open" or assessment.reachability != "reachable":
        return ServiceEntryHandoff(
            "unavailable",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "The endpoint is not confirmed open and reachable from this vantage",
            "Retest only within the existing approved scan plan",
        )
    if assessment.error_message is not None or not isinstance(assessment.observed_config, ObservedConfiguration):
        return ServiceEntryHandoff(
            "invalid_evidence",
            endpoint,
            False,
            None,
            None,
            probe_id,
            "The probe reported an error or has malformed observation data",
            "Reconcile the probe failure before routing",
        )
    if endpoint.transport != "tcp":
        return ServiceEntryHandoff(
            "unverified_protocol",
            endpoint,
            True,
            None,
            None,
            probe_id,
            "No UDP service identification is supported by this handoff",
            "Record the unassessed path or obtain approval for bounded UDP validation",
        )
    observation = assessment.observed_config
    services = _observed_services(observation)
    if not services:
        return ServiceEntryHandoff(
            "unverified_protocol",
            endpoint,
            True,
            None,
            None,
            probe_id,
            "Open port has no recognized protocol response; a fingerprint or port association is insufficient",
            "Record the unassessed path or obtain approval for a bounded identification action",
        )
    if len(services) != 1:
        return ServiceEntryHandoff(
            "conflicting_evidence",
            endpoint,
            True,
            None,
            None,
            probe_id,
            "Observed responses indicate multiple service families",
            "Reconcile conflicting evidence before specialist routing",
        )
    service, skill_id, validation = next(iter(services))
    if skill_id not in supported_skills:
        return ServiceEntryHandoff(
            "unsupported_route",
            endpoint,
            True,
            service,
            None,
            probe_id,
            "No registered specialist offers the required service skill",
            "Record the unsupported route and request an authorized routing implementation",
            skill_id=skill_id,
        )
    plan = ServiceValidationPlan(
        plan_id="",
        endpoint=endpoint,
        service=service,
        specialist=_SPECIALIST_ID,
        skill_id=skill_id,
        session_id=session.session_id,
        scope_reference=session.scope_reference,
        probe_key=probe_key,
        evidence_probe_id=probe_id,
        evidence_sha256=evidence_sha256,
        action=f"Validate {validation} on the exact endpoint",
        prerequisites=(
            "Bind the action to a validated engagement and an execution authorization for this exact endpoint",
            "Recheck DNS, worker identity, credential scope, approved method, and shared time/request/retry budgets",
            "Use low-impact read-only evidence collection before any controlled proof",
        ),
        expected_proof="Preserve protocol response, configuration/authentication evidence, and uncertainty with provenance",
        rollback="Remove only artifacts created by the approved action and verify cleanup independently",
        stop_conditions=(
            "Scope, identity, or authorization binding changes",
            "Budget exhausted or an external effect is uncertain",
            "Unexpected state change, sensitive data, or unsafe service response",
        ),
    )
    plan = replace(plan, plan_id=service_validation_plan_digest(plan))
    return ServiceEntryHandoff(
        "candidate",
        endpoint,
        True,
        service,
        _SPECIALIST_ID,
        probe_id,
        "Observed protocol response supports a candidate, not a vulnerability or successful use",
        "Bind this plan to the existing approved run, or request one bounded plan approval",
        skill_id=skill_id,
        plan=plan,
    )


def prepare_session_service_handoffs(
    session: ActiveScanSession,
    *,
    approved_endpoints: Collection[ApprovedEndpoint],
) -> list[ServiceEntryHandoff]:
    """Preserve discovery quarantine while routing each recorded assessment.

    The approved endpoint set must come from validated engagement scope, not the
    scan checkpoint. Quarantine in that checkpoint can only remove candidates.
    """
    try:
        quarantined_hosts = {_canonical_host(item.target_host) for item in session.quarantined_targets}
        session_targets = {_canonical_host(host) for host in session.approved_targets}
        assessment_probe_key_counts: dict[str, int] = {}
        for assessment in session.assessments:
            probe_key = ActiveScanSession.make_probe_key(
                assessment.vantage, assessment.protocol, assessment.target_host, assessment.port
            )
            assessment_probe_key_counts[probe_key] = assessment_probe_key_counts.get(probe_key, 0) + 1
        session_valid = (
            isinstance(session.session_id, str)
            and bool(session.session_id.strip())
            and session.session_id == session.session_id.strip()
            and len(session.session_id) <= 128
            and isinstance(session.scope_reference, str)
            and bool(session.scope_reference.strip())
            and session.scope_reference == session.scope_reference.strip()
            and len(session.scope_reference) <= 512
            and session.vantage in _VANTAGES
            and session.status in _SESSION_STATUSES
        )
    except (AttributeError, TypeError, ValueError):
        quarantined_hosts = set()
        session_targets = set()
        assessment_probe_key_counts = {}
        session_valid = False
    try:
        supported_skills = frozenset(get_specialist(_SPECIALIST_ID).skills)
    except (SpecialistCatalogError, OSError, ValueError):
        supported_skills = frozenset()
    approved = frozenset(approved_endpoints)
    return [
        _prepare_service_entry_handoff(
            assessment,
            session=session,
            approved_endpoints=approved,
            quarantined_hosts=quarantined_hosts,
            session_targets=session_targets,
            session_valid=session_valid,
            supported_skills=supported_skills,
            assessment_probe_key_counts=assessment_probe_key_counts,
        )
        for assessment in session.assessments
    ]
