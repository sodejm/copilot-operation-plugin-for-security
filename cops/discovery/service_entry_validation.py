"""Offline, evidence-gated handoff from discovery to service validation.

This module neither probes a service nor creates an execution authorization. The
coordinator must bind any proposed action to an approved engagement and budget.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Collection

from cops.evidence.canonical import EvidenceError, digest, timestamp

from .active_models import ActiveScanSession, ActiveServiceAssessment, ObservedConfiguration


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_VANTAGES = frozenset({"external", "internal", "egress_point", "cloud_tenant"})
_TRANSPORTS = frozenset({"tcp", "udp"})


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
    if (
        type(observation.http_status) is int
        and 100 <= observation.http_status <= 599
    ) or re.match(r"^HTTP/\d(?:\.\d)? [1-5]\d\d\b", banner):
        services.add(("http", "web-api-inventory-and-replay", "HTTP exposure and authentication boundaries"))
    return services


def prepare_service_entry_handoff(
    assessment: ActiveServiceAssessment,
    *,
    approved_endpoints: Collection[ApprovedEndpoint],
    quarantined_hosts: Collection[str] = (),
) -> ServiceEntryHandoff:
    """Prepare a bounded, non-executing validation candidate from one discovery result.

    The caller supplies endpoints derived from trusted engagement scope. This
    method checks exact host, resolved IP, port, transport and vantage; it does
    not infer approval from the assessment or issue an execution receipt.
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
            "blocked_scope", None, False, None, None, probe_id,
            "Discovery endpoint is malformed", "Repair the discovery evidence and revalidate engagement scope",
        )
    if endpoint not in approved_endpoints:
        return ServiceEntryHandoff(
            "blocked_scope", endpoint, False, None, None, probe_id,
            "Exact endpoint is outside the approved set", "Update and approve scope before any follow-on action",
        )
    quarantined = set()
    for host in quarantined_hosts:
        try:
            quarantined.add(_canonical_host(host))
        except ValueError:
            return ServiceEntryHandoff(
                "blocked_scope", endpoint, False, None, None, probe_id,
                "Quarantine contains a malformed host identity",
                "Reconcile the quarantine against trusted scope before any follow-on action",
            )
    if endpoint.host in quarantined:
        return ServiceEntryHandoff(
            "blocked_scope", endpoint, False, None, None, probe_id,
            "The host was quarantined after an identity or resolution change",
            "Resolve the quarantine against trusted scope before any follow-on action",
        )
    try:
        if not probe_id or probe_id != probe_id.strip() or len(probe_id) > 128:
            raise EvidenceError("invalid_probe_id")
        timestamp(assessment.timestamp_utc)
    except EvidenceError:
        return ServiceEntryHandoff(
            "invalid_evidence", endpoint, False, None, None, probe_id,
            "Discovery evidence has no valid probe identity or timestamp",
            "Repair or repeat discovery within approved scope",
        )
    if assessment.port_state != "open" or assessment.reachability != "reachable":
        return ServiceEntryHandoff(
            "unavailable", endpoint, False, None, None, probe_id,
            "The endpoint is not confirmed open and reachable from this vantage",
            "Retest only within the existing approved scan plan",
        )
    if assessment.error_message is not None or not isinstance(assessment.observed_config, ObservedConfiguration):
        return ServiceEntryHandoff(
            "invalid_evidence", endpoint, False, None, None, probe_id,
            "The probe reported an error or has malformed observation data",
            "Reconcile the probe failure before routing",
        )
    if endpoint.transport != "tcp":
        return ServiceEntryHandoff(
            "unverified_protocol", endpoint, True, None, None, probe_id,
            "No UDP service identification is supported by this handoff",
            "Record the unassessed path or obtain approval for bounded UDP validation",
        )
    observation = assessment.observed_config
    try:
        evidence_sha256 = digest(
            {
                "probe_id": probe_id,
                "port_state": assessment.port_state,
                "reachability": assessment.reachability,
                "timestamp_utc": assessment.timestamp_utc,
                "observed_config": observation.to_dict(),
                "provenance": assessment.provenance.to_dict() if assessment.provenance else None,
            },
            max_bytes=65536,
        )
    except (EvidenceError, AttributeError, TypeError, ValueError):
        return ServiceEntryHandoff(
            "invalid_evidence", endpoint, False, None, None, probe_id,
            "Observation cannot be safely bound to a bounded evidence digest",
            "Repair or repeat discovery within approved scope",
        )
    services = _observed_services(observation)
    if not services:
        return ServiceEntryHandoff(
            "unverified_protocol", endpoint, True, None, None, probe_id,
            "Open port has no recognized protocol response; a fingerprint or port association is insufficient",
            "Record the unassessed path or obtain approval for a bounded identification action",
        )
    if len(services) != 1:
        return ServiceEntryHandoff(
            "conflicting_evidence", endpoint, True, None, None, probe_id,
            "Observed responses indicate multiple service families",
            "Reconcile conflicting evidence before specialist routing",
        )
    service, specialist, validation = next(iter(services))
    identity = {
        "version": 1,
        "endpoint": asdict(endpoint),
        "probe_id": probe_id,
        "service": service,
        "evidence_sha256": evidence_sha256,
    }
    plan_id = digest(identity)
    plan = ServiceValidationPlan(
        plan_id=plan_id,
        endpoint=endpoint,
        service=service,
        specialist=specialist,
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
    return ServiceEntryHandoff(
        "candidate", endpoint, True, service, specialist, probe_id,
        "Observed protocol response supports a candidate, not a vulnerability or successful use",
        "Bind this plan to the existing approved run, or request one bounded plan approval",
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
    quarantined_hosts = {item.target_host for item in session.quarantined_targets}
    return [
        prepare_service_entry_handoff(
            assessment,
            approved_endpoints=approved_endpoints,
            quarantined_hosts=quarantined_hosts,
        )
        for assessment in session.assessments
    ]
