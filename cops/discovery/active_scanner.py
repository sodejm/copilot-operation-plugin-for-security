"""Active network scanner, probe dispatchers, rate limiting, and scope boundary enforcement."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from typing import Any, Callable

from cops.evidence.canonical import utc_now
from .active_models import (
    ActiveScanSession,
    ActiveServiceAssessment,
    ConfidenceLevel,
    ObservedConfiguration,
    ObservedTLS,
    PortState,
    Protocol,
    ScanBudget,
    ScanDelta,
    ScanVantage,
    ServiceReachability,
    TargetShiftQuarantine,
)
from .fingerprinter import infer_service_fingerprint


class ActiveScanError(Exception):
    """Base error for active discovery operations."""


def _create_tls_context() -> ssl.SSLContext:
    """Create a client TLS context that cannot negotiate deprecated protocol versions."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class ScopeViolationError(ActiveScanError):
    """Raised when active probe target is not permitted within approved boundaries."""


class ProbeDispatcher(ABC):
    """Abstract interface for active network probe dispatchers."""

    @abstractmethod
    def resolve_target(self, target_host: str) -> str:
        """Resolve a hostname to its IP address."""

    @abstractmethod
    def dispatch_probe(
        self,
        target_host: str,
        resolved_ip: str,
        port: int,
        protocol: str = "tcp",
        timeout: float = 2.0,
        vantage: str = "external",
    ) -> ActiveServiceAssessment:
        """Dispatch a single network probe to evaluate an approved host and port."""


class OfflineSyntheticDispatcher(ProbeDispatcher):
    """Deterministic, 100% offline synthetic probe dispatcher for tests and disposable environments."""

    def __init__(
        self,
        targets: dict[str, dict[str, Any]] | None = None,
        dns_map: dict[str, str] | None = None,
        simulated_rate_limit: bool = True,
    ) -> None:
        self.targets = targets or {}
        self.dns_map = dns_map or {}
        self.simulated_rate_limit = simulated_rate_limit
        self.dispatched_probes: list[dict[str, Any]] = []
        self.side_effect_count = 0
        self.dns_resolution_hooks: dict[str, Callable[[], str]] = {}

    def set_dns_hook(self, target_host: str, hook: Callable[[], str]) -> None:
        """Set a dynamic hook to simulate DNS changes or rebind attacks."""
        self.dns_resolution_hooks[target_host] = hook

    def resolve_target(self, target_host: str) -> str:
        if target_host in self.dns_resolution_hooks:
            return self.dns_resolution_hooks[target_host]()
        if target_host in self.dns_map:
            return self.dns_map[target_host]
        # If looks like an IP, return as-is
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_host):
            return target_host
        # Default deterministic IP
        h = hashlib.sha256(target_host.encode("utf-8")).hexdigest()
        return f"198.51.100.{int(h[:2], 16) % 250 + 1}"

    def dispatch_probe(
        self,
        target_host: str,
        resolved_ip: str,
        port: int,
        protocol: str = "tcp",
        timeout: float = 2.0,
        vantage: str = "external",
    ) -> ActiveServiceAssessment:
        self.side_effect_count += 1
        probe_key = ActiveScanSession.make_probe_key(vantage, protocol, target_host, port)
        timestamp = utc_now()
        probe_id = hashlib.sha256(f"{probe_key}:{timestamp}".encode("utf-8")).hexdigest()[:24]

        self.dispatched_probes.append({
            "probe_key": probe_key,
            "target_host": target_host,
            "resolved_ip": resolved_ip,
            "port": port,
            "protocol": protocol,
            "timestamp": timestamp,
        })

        # Lookup configured mock behavior for (target_host or resolved_ip, port)
        target_info = self.targets.get(target_host) or self.targets.get(resolved_ip) or {}
        port_info = target_info.get("ports", {}).get(port, {})

        # Check for simulated unreachable host
        if target_info.get("unreachable") or target_info.get("status") == "unreachable":
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.UNREACHABLE.value,
                reachability=ServiceReachability.UNREACHABLE.value,
                observed_config=ObservedConfiguration(),
                latency_ms=None,
                timestamp_utc=timestamp,
                error_message="Host network path unreachable",
            )

        # Check for simulated timeout / filtered port
        if port_info.get("state") == "filtered" or port_info.get("timeout"):
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.FILTERED.value,
                reachability=ServiceReachability.FILTERED.value,
                observed_config=ObservedConfiguration(),
                latency_ms=timeout * 1000.0,
                timestamp_utc=timestamp,
                error_message=f"Probe timed out after {timeout} seconds",
            )

        # Check for closed port
        if port_info.get("state") == "closed":
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.CLOSED.value,
                reachability=ServiceReachability.REACHABLE.value,
                observed_config=ObservedConfiguration(),
                latency_ms=5.0,
                timestamp_utc=timestamp,
                error_message="Connection refused by remote host",
            )

        # Port is open
        raw_banner = port_info.get("banner")
        banner_bytes = port_info.get("banner_bytes") or (raw_banner.encode("utf-8").hex() if raw_banner else None)
        http_headers = port_info.get("headers", {})
        http_status = port_info.get("http_status")
        tls_data = port_info.get("tls")
        observed_tls = ObservedTLS.from_dict(tls_data) if tls_data else None

        observed_config = ObservedConfiguration(
            raw_banner=raw_banner,
            banner_bytes=banner_bytes,
            http_status=http_status,
            http_headers=http_headers,
            tls=observed_tls,
            protocol_metadata=port_info.get("protocol_metadata", {}),
        )

        fingerprint = infer_service_fingerprint(target_host, port, protocol, observed_config)

        return ActiveServiceAssessment(
            probe_id=probe_id,
            target_host=target_host,
            resolved_ip=resolved_ip,
            port=port,
            protocol=protocol,
            vantage=vantage,
            port_state=PortState.OPEN.value,
            reachability=ServiceReachability.REACHABLE.value,
            observed_config=observed_config,
            inferred_fingerprint=fingerprint,
            latency_ms=port_info.get("latency_ms", 12.5),
            timestamp_utc=timestamp,
        )


class StandardSocketDispatcher(ProbeDispatcher):
    """Standard-library live TCP socket and TLS probe dispatcher."""

    def resolve_target(self, target_host: str) -> str:
        try:
            return socket.gethostbyname(target_host)
        except Exception as err:
            raise ActiveScanError(f"DNS resolution failed for {target_host}: {err}") from err

    def dispatch_probe(
        self,
        target_host: str,
        resolved_ip: str,
        port: int,
        protocol: str = "tcp",
        timeout: float = 2.0,
        vantage: str = "external",
    ) -> ActiveServiceAssessment:
        probe_key = ActiveScanSession.make_probe_key(vantage, protocol, target_host, port)
        timestamp = utc_now()
        probe_id = hashlib.sha256(f"{probe_key}:{timestamp}".encode("utf-8")).hexdigest()[:24]

        start_time = time.monotonic()
        sock = None
        try:
            sock = socket.create_connection((resolved_ip, port), timeout=timeout)
            latency_ms = (time.monotonic() - start_time) * 1000.0

            raw_banner = None
            banner_bytes = None
            observed_tls = None
            http_status = None
            http_headers = {}

            # If TLS port (443, 8443) or requested
            if port in (443, 8443):
                ctx = _create_tls_context()
                try:
                    with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                        cipher = ssock.cipher()
                        proto_ver = ssock.version()
                        cert = ssock.getpeercert(binary_form=True)

                        observed_tls = ObservedTLS(
                            version=proto_ver,
                            cipher_suite=cipher[0] if cipher else None,
                        )
                except Exception:
                    pass

            observed_config = ObservedConfiguration(
                raw_banner=raw_banner,
                banner_bytes=banner_bytes,
                http_status=http_status,
                http_headers=http_headers,
                tls=observed_tls,
            )

            fingerprint = infer_service_fingerprint(target_host, port, protocol, observed_config)

            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.OPEN.value,
                reachability=ServiceReachability.REACHABLE.value,
                observed_config=observed_config,
                inferred_fingerprint=fingerprint,
                latency_ms=latency_ms,
                timestamp_utc=timestamp,
            )
        except socket.timeout:
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.FILTERED.value,
                reachability=ServiceReachability.FILTERED.value,
                observed_config=ObservedConfiguration(),
                latency_ms=timeout * 1000.0,
                timestamp_utc=timestamp,
                error_message="Socket connection timed out",
            )
        except (ConnectionRefusedError, OSError) as err:
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.CLOSED.value,
                reachability=ServiceReachability.REACHABLE.value,
                observed_config=ObservedConfiguration(),
                latency_ms=None,
                timestamp_utc=timestamp,
                error_message=str(err),
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


class ActiveScanner:
    """Bounded, resumable active assessment engine with scope and rate enforcement."""

    def __init__(
        self,
        session: ActiveScanSession,
        dispatcher: ProbeDispatcher,
        scope: dict[str, Any] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.session = session
        self.dispatcher = dispatcher
        self.scope = scope or {}
        self.sleeper = sleeper

    def _is_ip_in_scope(self, ip_str: str) -> bool:
        """Verify whether an IP address falls within approved scope networks and not excluded."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        # Exclusions first
        exclusions = self.scope.get("exclusions", {})
        for exc_range in exclusions.get("ip_ranges", []):
            try:
                if addr in ipaddress.ip_network(exc_range, strict=False):
                    return False
            except ValueError:
                continue

        # In-scope ranges
        scope_ranges = self.scope.get("ip_ranges", [])
        if not scope_ranges:
            # If no IP ranges specified in scope, default to allowed if approved_targets match
            return True

        for s_range in scope_ranges:
            try:
                if addr in ipaddress.ip_network(s_range, strict=False):
                    return True
            except ValueError:
                continue

        return False

    def _is_host_in_scope(self, host: str) -> bool:
        """Verify whether target host is allowed and not excluded."""
        host_lower = host.lower()
        exclusions = self.scope.get("exclusions", {})
        for exc_domain in exclusions.get("domains", []):
            if host_lower == exc_domain.lower() or host_lower.endswith("." + exc_domain.lower()):
                return False

        domains = self.scope.get("domains", [])
        if not domains:
            return True

        for d in domains:
            d_lower = d.lower()
            if host_lower == d_lower or host_lower.endswith("." + d_lower):
                return True

        return False

    def run(self) -> ActiveScanSession:
        """Execute or resume bounded active assessment across approved targets and ports."""
        budget = self.session.budget
        inter_probe_interval = 1.0 / budget.rate_limit_pps if budget.rate_limit_pps > 0 else 0.0
        start_time = time.monotonic()
        targets_assessed = 0

        self.session.status = "in_progress"

        for target_host in self.session.approved_targets:
            # Check target budget
            if budget.max_targets and targets_assessed >= budget.max_targets:
                self.session.status = "budget_exhausted"
                break

            # 1. Validate target host against scope
            if self.scope and not self._is_host_in_scope(target_host):
                self.session.quarantined_targets.append(
                    TargetShiftQuarantine(
                        target_host=target_host,
                        original_ip=None,
                        new_ip="unresolved",
                        reason="outside_scope",
                        timestamp_utc=utc_now(),
                    )
                )
                continue

            # 2. Resolve target and check for DNS change / out-of-scope shift
            try:
                resolved_ip = self.dispatcher.resolve_target(target_host)
            except Exception as err:
                self.session.quarantined_targets.append(
                    TargetShiftQuarantine(
                        target_host=target_host,
                        original_ip=None,
                        new_ip="unresolved",
                        reason=f"dns_resolution_failed: {err}",
                        timestamp_utc=utc_now(),
                    )
                )
                continue

            if self.scope and not self._is_ip_in_scope(resolved_ip):
                # DNS resolved to an IP outside approved boundaries -> quarantine target immediately
                self.session.quarantined_targets.append(
                    TargetShiftQuarantine(
                        target_host=target_host,
                        original_ip=None,
                        new_ip=resolved_ip,
                        reason="dns_rebind_detected",
                        timestamp_utc=utc_now(),
                    )
                )
                continue

            targets_assessed += 1

            for port in self.session.approved_ports:
                # 3. Check time budget
                if budget.max_total_seconds is not None:
                    elapsed = time.monotonic() - start_time
                    if elapsed >= budget.max_total_seconds:
                        self.session.status = "budget_exhausted"
                        return self.session

                # 4. Check Resumability: skip already completed probe keys
                probe_key = ActiveScanSession.make_probe_key(
                    self.session.vantage, Protocol.TCP.value, target_host, port
                )
                if probe_key in self.session.completed_probe_keys:
                    # Idempotent skip: do not repeat side effect
                    continue

                # 5. Dispatch probe
                assessment = self.dispatcher.dispatch_probe(
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    port=port,
                    protocol=Protocol.TCP.value,
                    timeout=budget.timeout_seconds,
                    vantage=self.session.vantage,
                )

                # Record assessment and update session side-effect ledger
                self.session.completed_probe_keys.add(probe_key)
                self.session.assessments.append(assessment)
                self.session.total_probes_dispatched += 1
                self.session.total_side_effects += 1

                # 6. Enforce rate limiting
                if inter_probe_interval > 0:
                    self.sleeper(inter_probe_interval)

        if self.session.status == "in_progress":
            self.session.status = "completed"
        self.session.completed_at = utc_now()
        return self.session


def compare_active_scans(baseline: ActiveScanSession, current: ActiveScanSession) -> ScanDelta:
    """Compare baseline scan against current scan to compute remediated and altered exposures."""
    baseline_open: dict[str, ActiveServiceAssessment] = {}
    for a in baseline.assessments:
        if a.port_state == PortState.OPEN.value:
            key = f"{a.target_host}:{a.port}"
            baseline_open[key] = a

    current_open: dict[str, ActiveServiceAssessment] = {}
    current_all: dict[str, ActiveServiceAssessment] = {}
    for a in current.assessments:
        key = f"{a.target_host}:{a.port}"
        current_all[key] = a
        if a.port_state == PortState.OPEN.value:
            current_open[key] = a

    remediated: list[dict[str, Any]] = []
    persistent: list[dict[str, Any]] = []
    new_exp: list[dict[str, Any]] = []
    fingerprint_changes: list[dict[str, Any]] = []

    for key, base_a in baseline_open.items():
        curr_a = current_all.get(key)
        if not curr_a or curr_a.port_state != PortState.OPEN.value:
            remediated.append({
                "target_host": base_a.target_host,
                "port": base_a.port,
                "previous_state": base_a.port_state,
                "current_state": curr_a.port_state if curr_a else "not_probed",
                "service": base_a.inferred_fingerprint.service_name if base_a.inferred_fingerprint else "unknown",
            })
        else:
            persistent.append({
                "target_host": curr_a.target_host,
                "port": curr_a.port,
                "state": curr_a.port_state,
                "service": curr_a.inferred_fingerprint.service_name if curr_a.inferred_fingerprint else "unknown",
            })
            # Check for version / fingerprint changes
            base_fp = base_a.inferred_fingerprint
            curr_fp = curr_a.inferred_fingerprint
            if base_fp and curr_fp and (base_fp.product != curr_fp.product or base_fp.version != curr_fp.version):
                fingerprint_changes.append({
                    "target_host": curr_a.target_host,
                    "port": curr_a.port,
                    "previous_product": base_fp.product,
                    "previous_version": base_fp.version,
                    "current_product": curr_fp.product,
                    "current_version": curr_fp.version,
                })

    for key, curr_a in current_open.items():
        if key not in baseline_open:
            new_exp.append({
                "target_host": curr_a.target_host,
                "port": curr_a.port,
                "state": curr_a.port_state,
                "service": curr_a.inferred_fingerprint.service_name if curr_a.inferred_fingerprint else "unknown",
            })

    total_baseline = len(baseline_open)
    remediation_rate = (len(remediated) / total_baseline) * 100.0 if total_baseline > 0 else 0.0

    return ScanDelta(
        baseline_session_id=baseline.session_id,
        current_session_id=current.session_id,
        remediated_exposures=remediated,
        new_exposures=new_exp,
        persistent_exposures=persistent,
        fingerprint_changes=fingerprint_changes,
        remediation_rate=round(remediation_rate, 2),
    )
