"""Active network scanner, probe dispatchers, rate limiting, and scope boundary enforcement."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import math
import os
import select
import socket
import ssl
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cops.evidence.canonical import utc_now

from .active_models import (
    ActiveScanSession,
    ActiveServiceAssessment,
    ObservedConfiguration,
    ObservedTLS,
    PortState,
    Protocol,
    ScanBudget,
    ScanDelta,
    ServiceReachability,
    TargetShiftQuarantine,
)
from .fingerprinter import infer_service_fingerprint
from .models import EvidenceProvenance


class ActiveScanError(Exception):
    """Base error for active discovery operations."""


@contextmanager
def _live_checkpoint_lock(path: Path) -> Iterator[None]:
    """Hold one cross-process controller lock for the whole live scan."""
    lock_path = path.with_name(f"{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as err:
            raise ActiveScanError("Live checkpoint has another active controller; retry after it stops") from err
        yield
    finally:
        if acquired:
            if os.name == "nt":
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _create_tls_context() -> ssl.SSLContext:
    """Create a TLS observation context; this does not authenticate the peer."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _record_local_probe(assessment: ActiveServiceAssessment) -> ActiveServiceAssessment:
    """Hash the local result for traceability without claiming remote attestation."""
    record = json.dumps(assessment.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    assessment.provenance = EvidenceProvenance(
        source_id=assessment.probe_id,
        source_type="unattested_local_socket_observation",
        sha256=hashlib.sha256(record).hexdigest(),
        timestamp=assessment.timestamp_utc,
        path_or_uri=f"probe://{assessment.probe_id}",
        raw_record_ref="assessment_without_provenance",
    )
    return assessment


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
        # Literal addresses, including IPv6, need no synthetic DNS lookup.
        try:
            ipaddress.ip_address(target_host)
            return target_host
        except ValueError:
            pass
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
        probe_id = hashlib.sha256(f"{probe_key}:{timestamp}".encode()).hexdigest()[:24]

        self.dispatched_probes.append(
            {
                "probe_key": probe_key,
                "target_host": target_host,
                "resolved_ip": resolved_ip,
                "port": port,
                "protocol": protocol,
                "timestamp": timestamp,
            }
        )

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
    """Standard-library live TCP and bounded UDP probe dispatcher."""

    def __init__(self, udp_dns_probe_ports: list[int] | None = None) -> None:
        self.udp_dns_probe_ports = frozenset(udp_dns_probe_ports or [])

    def resolve_target(self, target_host: str) -> str:
        try:
            return str(ipaddress.ip_address(target_host))
        except ValueError:
            pass
        try:
            addresses = socket.getaddrinfo(target_host, None, type=socket.SOCK_STREAM)
            return str(ipaddress.ip_address(addresses[0][4][0]))
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
        if protocol == Protocol.UDP.value:
            return _record_local_probe(self._dispatch_udp(target_host, resolved_ip, port, timeout, vantage))
        if protocol != Protocol.TCP.value:
            raise ActiveScanError(f"Unsupported live probe protocol: {protocol}")
        probe_key = ActiveScanSession.make_probe_key(vantage, protocol, target_host, port)
        timestamp = utc_now()
        probe_id = hashlib.sha256(f"{probe_key}:{timestamp}".encode()).hexdigest()[:24]

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
            protocol_metadata: dict[str, Any] = {}

            # A passive, bounded server-first read uses no application request.
            # TLS ports instead start their handshake immediately.
            if port in (443, 8443):
                protocol_metadata["tls_certificate_validation"] = "not_performed"
                ctx = _create_tls_context()
                try:
                    with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                        cipher = ssock.cipher()
                        proto_ver = ssock.version()

                        observed_tls = ObservedTLS(
                            version=proto_ver,
                            cipher_suite=cipher[0] if cipher else None,
                        )
                except (OSError, ssl.SSLError):
                    # Failed TLS negotiation leaves observed_tls unset.
                    pass
            else:
                banner_wait = min(timeout, 0.05)
                protocol_metadata["banner_probe"] = "server_first_no_payload"
                protocol_metadata["banner_wait_seconds"] = banner_wait
                try:
                    readable, _, _ = select.select([sock], [], [], banner_wait)
                    if readable:
                        response = sock.recv(512)
                        if response:
                            banner_bytes = response.hex()
                            decoded = response.decode("utf-8", errors="replace")
                            raw_banner = "".join(
                                char if char.isprintable() or char in "\r\n\t" else "\ufffd" for char in decoded
                            )
                            protocol_metadata["banner_bytes_observed"] = len(response)
                except (OSError, TimeoutError):
                    # An established TCP connection remains open even if its
                    # optional banner cannot be read.
                    protocol_metadata["banner_read_error"] = "read_failed"

            observed_config = ObservedConfiguration(
                raw_banner=raw_banner,
                banner_bytes=banner_bytes,
                http_status=http_status,
                http_headers=http_headers,
                tls=observed_tls,
                protocol_metadata=protocol_metadata,
            )

            fingerprint = infer_service_fingerprint(target_host, port, protocol, observed_config)

            return _record_local_probe(
                ActiveServiceAssessment(
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
            )
        except TimeoutError:
            return _record_local_probe(
                ActiveServiceAssessment(
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
            )
        except OSError as err:
            refused = err.errno == errno.ECONNREFUSED
            no_route = err.errno in {
                errno.ENETUNREACH,
                errno.EHOSTUNREACH,
                errno.ENETDOWN,
                errno.EHOSTDOWN,
            }
            return _record_local_probe(
                ActiveServiceAssessment(
                    probe_id=probe_id,
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    port=port,
                    protocol=protocol,
                    vantage=vantage,
                    port_state=(
                        PortState.CLOSED.value
                        if refused
                        else PortState.UNREACHABLE.value
                        if no_route
                        else PortState.UNKNOWN.value
                    ),
                    reachability=(
                        ServiceReachability.REACHABLE.value
                        if refused
                        else ServiceReachability.UNREACHABLE.value
                        if no_route
                        else ServiceReachability.UNKNOWN.value
                    ),
                    observed_config=ObservedConfiguration(),
                    latency_ms=None,
                    timestamp_utc=timestamp,
                    error_message=str(err),
                )
            )
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    # Closing a failed probe must not replace its result.
                    pass

    def _dispatch_udp(
        self, target_host: str, resolved_ip: str, port: int, timeout: float, vantage: str
    ) -> ActiveServiceAssessment:
        """Send one approved datagram; silence never establishes an open port."""
        protocol = Protocol.UDP.value
        probe_key = ActiveScanSession.make_probe_key(vantage, protocol, target_host, port)
        timestamp = utc_now()
        probe_id = hashlib.sha256(f"{probe_key}:{timestamp}".encode()).hexdigest()[:24]
        dns_probe = port in self.udp_dns_probe_ports
        query_id = os.urandom(2) if dns_probe else b""
        payload = query_id + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01" if dns_probe else b""
        probe_name = "dns_root_ns_query" if dns_probe else "empty_datagram"
        start_time = time.monotonic()
        sock = None
        try:
            family = socket.AF_INET6 if ipaddress.ip_address(resolved_ip).version == 6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.connect((resolved_ip, port))
            sock.send(payload)
            response = sock.recv(512)
            dns_validated = bool(
                dns_probe
                and len(response) >= 17
                and response[:2] == query_id
                and (response[2] & 0x80)
                and not (response[2] & 0x78)
                and not (response[3] & 0x40)
                and response[4:6] == b"\x00\x01"
                and response[12:17] == payload[12:17]
            )
            observed = ObservedConfiguration(
                protocol_metadata={
                    "probe_payload": probe_name,
                    "response_prefix_bytes": len(response),
                    "response_prefix_sha256": hashlib.sha256(response).hexdigest(),
                    **(
                        {
                            "dns_response_validated": dns_validated,
                            "dns_response_truncated": dns_validated and bool(response[2] & 0x02),
                        }
                        if dns_probe
                        else {}
                    ),
                }
            )
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.OPEN.value,
                reachability=ServiceReachability.REACHABLE.value,
                observed_config=observed,
                inferred_fingerprint=infer_service_fingerprint(target_host, port, protocol, observed),
                latency_ms=(time.monotonic() - start_time) * 1000.0,
                timestamp_utc=timestamp,
            )
        except TimeoutError:
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=PortState.UNKNOWN.value,
                reachability=ServiceReachability.UNKNOWN.value,
                observed_config=ObservedConfiguration(),
                latency_ms=(time.monotonic() - start_time) * 1000.0,
                timestamp_utc=timestamp,
                error_message=f"No UDP response to {probe_name}; open or filtered cannot be distinguished",
            )
        except OSError as err:
            refused = err.errno == errno.ECONNREFUSED
            no_route = err.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.EHOSTDOWN}
            return ActiveServiceAssessment(
                probe_id=probe_id,
                target_host=target_host,
                resolved_ip=resolved_ip,
                port=port,
                protocol=protocol,
                vantage=vantage,
                port_state=(
                    PortState.CLOSED.value
                    if refused
                    else PortState.UNREACHABLE.value
                    if no_route
                    else PortState.UNKNOWN.value
                ),
                reachability=(
                    ServiceReachability.REACHABLE.value
                    if refused
                    else ServiceReachability.UNREACHABLE.value
                    if no_route
                    else ServiceReachability.UNKNOWN.value
                ),
                observed_config=ObservedConfiguration(),
                latency_ms=(time.monotonic() - start_time) * 1000.0,
                timestamp_utc=timestamp,
                error_message=str(err),
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    # Closing a failed probe must not replace its result.
                    pass


class ActiveScanner:
    """Bounded, resumable active assessment engine with scope and rate enforcement."""

    def __init__(
        self,
        session: ActiveScanSession,
        dispatcher: ProbeDispatcher,
        scope: dict[str, Any] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        checkpoint: Path | str | None = None,
    ) -> None:
        self.session = session
        self.dispatcher = dispatcher
        # Any custom dispatcher may have network side effects. Only the exact
        # built-in synthetic dispatcher can bypass live admission and locking.
        self._live_dispatcher = type(dispatcher) is not OfflineSyntheticDispatcher
        self.scope = scope if scope is not None else {}
        self.sleeper = sleeper
        # A live checkpoint and its controller lock must share the same name
        # even when a caller supplies a symlink or a relative path.
        self.checkpoint = Path(checkpoint).resolve() if checkpoint is not None else None

    def _validate_run(self) -> None:
        budget = self.session.budget
        if not self.session.approved_targets or not (self.session.approved_ports or self.session.approved_udp_ports):
            raise ActiveScanError("A scan needs explicit targets and TCP or UDP ports")
        if any(not isinstance(target, str) or not target.strip() for target in self.session.approved_targets):
            raise ActiveScanError("Targets must be nonempty hostnames or IP addresses")
        if any(
            not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
            for port in self.session.approved_ports + self.session.approved_udp_ports
        ):
            raise ActiveScanError("TCP and UDP ports must be integers from 1 through 65535")
        if len({target.lower() for target in self.session.approved_targets}) != len(
            self.session.approved_targets
        ) or any(
            len(set(ports)) != len(ports) for ports in (self.session.approved_ports, self.session.approved_udp_ports)
        ):
            raise ActiveScanError("Duplicate targets or ports would repeat probe side effects")
        dns_ports = self.session.udp_dns_probe_ports
        if (
            any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in dns_ports)
            or len(set(dns_ports)) != len(dns_ports)
            or not set(dns_ports).issubset(self.session.approved_udp_ports)
        ):
            raise ActiveScanError("DNS probe ports must be unique approved UDP ports")
        self._validate_dns_probe_profile()
        if (
            not isinstance(budget.timeout_seconds, (int, float))
            or isinstance(budget.timeout_seconds, bool)
            or not math.isfinite(budget.timeout_seconds)
            or budget.timeout_seconds <= 0
            or not isinstance(budget.rate_limit_pps, (int, float))
            or isinstance(budget.rate_limit_pps, bool)
            or not math.isfinite(budget.rate_limit_pps)
            or budget.rate_limit_pps < 0
        ):
            raise ActiveScanError("Probe timeout must be positive and rate limit nonnegative")
        if budget.max_total_seconds is not None and (
            not isinstance(budget.max_total_seconds, (int, float))
            or isinstance(budget.max_total_seconds, bool)
            or not math.isfinite(budget.max_total_seconds)
            or budget.max_total_seconds <= 0
        ):
            raise ActiveScanError("Execution duration must be positive")
        if budget.max_targets is not None and (
            isinstance(budget.max_targets, bool)
            or not isinstance(budget.max_targets, int)
            or budget.max_targets <= 0
            or len(self.session.approved_targets) > budget.max_targets
        ):
            raise ActiveScanError("Approved target count exceeds its cumulative target cap")
        if isinstance(budget.max_retries, bool) or not isinstance(budget.max_retries, int) or budget.max_retries < 0:
            raise ActiveScanError("Retry limit must be a nonnegative integer")
        if isinstance(budget.max_probes, bool) or not isinstance(budget.max_probes, int) or budget.max_probes <= 0:
            raise ActiveScanError("A positive cumulative probe cap is required")
        if not isinstance(self.scope, dict):
            raise ActiveScanError("Scope must be a JSON object")
        if self._live_dispatcher:
            if self.checkpoint is None:
                raise ActiveScanError("Live scanning requires a durable checkpoint path")
            if budget.rate_limit_pps <= 0:
                raise ActiveScanError("Live scanning requires a positive probe rate limit")
            if budget.max_total_seconds is None:
                raise ActiveScanError("Live scanning requires an explicit execution duration")
            ranges = self.scope.get("ip_ranges")
            if not isinstance(ranges, list) or not ranges:
                raise ActiveScanError("Live scanning requires explicit approved IP ranges")
            try:
                for key in ("domains",):
                    value = self.scope.get(key, [])
                    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                        raise ValueError(f"{key} must be a list of strings")
                for item in ranges:
                    ipaddress.ip_network(item, strict=False)
                exclusions = self.scope.get("exclusions", {})
                if not isinstance(exclusions, dict):
                    raise ValueError("exclusions must be an object")
                exc_domains = exclusions.get("domains", [])
                if not isinstance(exc_domains, list) or any(not isinstance(item, str) for item in exc_domains):
                    raise ValueError("exclusions.domains must be a list of strings")
                exc_ranges = exclusions.get("ip_ranges", [])
                if not isinstance(exc_ranges, list):
                    raise ValueError("exclusions.ip_ranges must be a list")
                for item in exc_ranges:
                    ipaddress.ip_network(item, strict=False)
            except (TypeError, ValueError) as err:
                raise ActiveScanError(f"Invalid live IP scope: {err}") from err

    def _live_plan_digest(self) -> str:
        plan = {
            "session_id": self.session.session_id,
            "scope_reference": self.session.scope_reference,
            "approved_targets": self.session.approved_targets,
            "approved_ports": self.session.approved_ports,
            "vantage": self.session.vantage,
            # Normalize numeric budget fields exactly as checkpoint loading does.
            # JSON distinguishes 10 from 10.0, though both admit the same rate.
            "budget": ScanBudget.from_dict(self.session.budget.to_dict()).to_dict(),
            "scope": self.scope,
        }
        # Preserve digests for existing TCP-only checkpoints.
        if self.session.approved_udp_ports:
            plan["approved_udp_ports"] = self.session.approved_udp_ports
        if self.session.udp_dns_probe_ports:
            plan["udp_dns_probe_ports"] = self.session.udp_dns_probe_ports
        encoded = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _validate_dns_probe_profile(self) -> None:
        """Keep the live dispatcher's payload selection bound to the approved plan."""
        if not self._live_dispatcher:
            return
        configured = getattr(self.dispatcher, "udp_dns_probe_ports", None)
        if self.session.udp_dns_probe_ports or configured is not None:
            if not isinstance(configured, frozenset) or configured != frozenset(self.session.udp_dns_probe_ports):
                raise ActiveScanError("Live UDP DNS probe selection differs from the approved plan")

    def _validate_probe_evidence(self, assessment: ActiveServiceAssessment) -> None:
        """Reject results that claim an unapproved UDP application payload."""
        metadata = assessment.observed_config.protocol_metadata
        if not isinstance(metadata, dict):
            raise ActiveScanError("Probe result has invalid protocol metadata")
        if assessment.protocol != Protocol.UDP.value:
            if "probe_payload" in metadata and metadata["probe_payload"] == "dns_root_ns_query":
                raise ActiveScanError("Probe result claims an out-of-plan DNS payload")
            return
        expected = "dns_root_ns_query" if assessment.port in self.session.udp_dns_probe_ports else "empty_datagram"
        if "probe_payload" in metadata and metadata["probe_payload"] != expected:
            raise ActiveScanError("Probe result claims an out-of-plan UDP payload")
        if (
            any(isinstance(key, str) and key.startswith("dns_response_") for key in metadata)
            and expected != "dns_root_ns_query"
        ):
            raise ActiveScanError("Probe result claims unapproved DNS response evidence")
        if assessment.port_state == PortState.OPEN.value and expected == "dns_root_ns_query":
            if metadata.get("probe_payload") != expected or not isinstance(
                metadata.get("dns_response_validated"), bool
            ):
                raise ActiveScanError("Open DNS probe result lacks payload provenance")

    def _validate_live_ledger(self) -> None:
        """Reject a contradictory checkpoint before any resumed network activity."""
        session = self.session
        completed = session.completed_probe_keys
        pending = session.pending_probe_keys
        planned_ports = {
            Protocol.TCP.value: set(session.approved_ports),
            Protocol.UDP.value: set(session.approved_udp_ports),
        }
        targets = {target.lower() for target in session.approved_targets}

        def planned_key(key: str) -> bool:
            if not isinstance(key, str):
                return False
            protocol = next((name for name in planned_ports if key.startswith(f"{session.vantage}:{name}:")), None)
            if protocol is None:
                return False
            prefix = f"{session.vantage}:{protocol}:"
            host, separator, port_text = key[len(prefix) :].rpartition(":")
            return bool(
                separator
                and host in targets
                and port_text.isdecimal()
                and int(port_text) in planned_ports[protocol]
                and key == ActiveScanSession.make_probe_key(session.vantage, protocol, host, int(port_text))
            )

        if completed & pending or any(not planned_key(key) for key in completed | pending):
            raise ActiveScanError("Live checkpoint has overlapping or out-of-plan probe keys")
        if (
            not isinstance(session.total_probes_dispatched, int)
            or isinstance(session.total_probes_dispatched, bool)
            or not isinstance(session.total_side_effects, int)
            or isinstance(session.total_side_effects, bool)
            or session.total_probes_dispatched != len(completed) + len(pending)
            or session.total_side_effects != len(completed)
            or session.total_probes_dispatched > session.budget.max_probes
            or not isinstance(session.elapsed_seconds, (int, float))
            or isinstance(session.elapsed_seconds, bool)
            or not math.isfinite(session.elapsed_seconds)
            or session.elapsed_seconds < 0
        ):
            raise ActiveScanError("Live checkpoint probe accounting is inconsistent")

        assessment_keys: set[str] = set()
        for assessment in session.assessments:
            key = ActiveScanSession.make_probe_key(
                assessment.vantage, assessment.protocol, assessment.target_host, assessment.port
            )
            if (
                key not in completed
                or key in assessment_keys
                or assessment.target_host.lower() not in targets
                or not self._is_ip_in_scope(assessment.resolved_ip)
            ):
                raise ActiveScanError("Live checkpoint assessment evidence is inconsistent")
            try:
                self._validate_probe_evidence(assessment)
            except ActiveScanError as err:
                raise ActiveScanError("Live checkpoint probe evidence is inconsistent") from err
            assessment_keys.add(key)
        if assessment_keys != completed:
            raise ActiveScanError("Live checkpoint lacks assessment evidence for completed probes")

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

        # A literal address is governed by the CIDR allowlist, even when the
        # same engagement also lists domain suffixes for hostname targets.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return self._is_ip_in_scope(host)

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
        self._validate_run()
        if self._live_dispatcher:
            with _live_checkpoint_lock(Path(self.checkpoint)):
                return self._run_validated()
        return self._run_validated()

    def _run_validated(self) -> ActiveScanSession:
        if self.session.bound_plan_sha256 and not self._live_dispatcher:
            raise ActiveScanError("A live checkpoint cannot resume with a synthetic dispatcher")
        if self._live_dispatcher:
            digest = self._live_plan_digest()
            if self.session.bound_plan_sha256 is None:
                if (
                    self.session.total_probes_dispatched
                    or self.session.completed_probe_keys
                    or self.session.pending_probe_keys
                ):
                    raise ActiveScanError("Prior live activity has no bound plan; reconcile before continuing")
                if Path(self.checkpoint).exists():
                    raise ActiveScanError("Live scan checkpoint already exists; resume it or choose a new path")
                self.session.bound_plan_sha256 = digest
            elif self.session.bound_plan_sha256 != digest:
                raise ActiveScanError("Live plan or scope changed since checkpoint; a new approved plan is required")
            elif not Path(self.checkpoint).exists():
                raise ActiveScanError("Bound live session has no checkpoint; reconcile before continuing")
            else:
                try:
                    durable = ActiveScanSession.load_checkpoint(self.checkpoint)
                except (OSError, ValueError, TypeError, KeyError) as err:
                    raise ActiveScanError("Live checkpoint cannot be verified; reconcile before continuing") from err
                if durable.to_dict() != self.session.to_dict():
                    raise ActiveScanError("Live checkpoint differs from supplied session; reload before continuing")
            self._validate_live_ledger()
        if self.session.pending_probe_keys:
            self.session.status = "requires_reconciliation"
            if self.checkpoint is not None:
                self.session.save_checkpoint(self.checkpoint)
            return self.session
        budget = self.session.budget
        inter_probe_interval = 1.0 / budget.rate_limit_pps if budget.rate_limit_pps > 0 else 0.0
        # On a resume, conservatively wait one full interval before the next
        # dispatch. The prior controller may have stopped before its sleep.
        prior_dispatch = self.session.total_probes_dispatched > 0
        start_time = time.monotonic()
        elapsed_before_run = self.session.elapsed_seconds

        def persist() -> None:
            self.session.elapsed_seconds = elapsed_before_run + (time.monotonic() - start_time)
            if self.checkpoint is not None:
                self.session.save_checkpoint(self.checkpoint)

        self.session.status = "in_progress"
        persist()
        planned_probes = [(Protocol.TCP.value, port) for port in self.session.approved_ports] + [
            (Protocol.UDP.value, port) for port in self.session.approved_udp_ports
        ]

        for target_host in self.session.approved_targets:
            # A quarantined target stays halted across checkpoint resumes.
            if any(q.target_host.lower() == target_host.lower() for q in self.session.quarantined_targets):
                continue

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
                persist()
                continue

            # A resumed target remains pinned to the address used by its prior
            # probes. Completed keys without assessment evidence cannot prove
            # which address received those side effects.
            prior_ips = {
                a.resolved_ip for a in self.session.assessments if a.target_host.lower() == target_host.lower()
            }
            prior_ip = next(iter(prior_ips)) if len(prior_ips) == 1 else None
            probe_prefixes = tuple(
                f"{self.session.vantage}:{protocol}:{target_host.lower()}:"
                for protocol, ports in (
                    (Protocol.TCP.value, self.session.approved_ports),
                    (Protocol.UDP.value, self.session.approved_udp_ports),
                )
                if ports
            )
            has_completed_probe = any(key.startswith(probe_prefixes) for key in self.session.completed_probe_keys)
            if len(prior_ips) > 1 or (has_completed_probe and prior_ip is None):
                self.session.quarantined_targets.append(
                    TargetShiftQuarantine(
                        target_host=target_host,
                        original_ip=prior_ip,
                        new_ip="unresolved",
                        reason="checkpoint_missing_resolution",
                        timestamp_utc=utc_now(),
                    )
                )
                persist()
                continue

            # A fully completed target needs no further DNS lookup or network
            # activity. This also makes a repeated resume side-effect free.
            if all(
                ActiveScanSession.make_probe_key(self.session.vantage, protocol, target_host, port)
                in self.session.completed_probe_keys
                for protocol, port in planned_probes
            ):
                continue

            # 2. Resolve target and check for DNS change / out-of-scope shift
            try:
                resolved_ip = self.dispatcher.resolve_target(target_host)
            except Exception as err:
                self.session.quarantined_targets.append(
                    TargetShiftQuarantine(
                        target_host=target_host,
                        original_ip=prior_ip,
                        new_ip="unresolved",
                        reason=f"dns_resolution_failed: {err}",
                        timestamp_utc=utc_now(),
                    )
                )
                persist()
                continue

            if prior_ip is not None and resolved_ip != prior_ip:
                self.session.quarantined_targets.append(
                    TargetShiftQuarantine(
                        target_host=target_host,
                        original_ip=prior_ip,
                        new_ip=resolved_ip,
                        reason="dns_rebind_detected",
                        timestamp_utc=utc_now(),
                    )
                )
                persist()
                continue

            if self.scope and not self._is_ip_in_scope(resolved_ip):
                # DNS resolved to an IP outside approved boundaries -> quarantine target immediately
                self.session.quarantined_targets.append(
                    TargetShiftQuarantine(
                        target_host=target_host,
                        original_ip=prior_ip,
                        new_ip=resolved_ip,
                        reason="dns_rebind_detected",
                        timestamp_utc=utc_now(),
                    )
                )
                persist()
                continue

            probes_for_target = 0

            for protocol, port in planned_probes:
                # 3. Skip completed operations before checking whether another
                # dispatch is within the remaining cumulative budget.
                probe_key = ActiveScanSession.make_probe_key(self.session.vantage, protocol, target_host, port)
                if probe_key in self.session.completed_probe_keys:
                    continue

                # 4. Check time budget
                if budget.max_total_seconds is not None:
                    elapsed = elapsed_before_run + (time.monotonic() - start_time)
                    if elapsed >= budget.max_total_seconds:
                        self.session.status = "budget_exhausted"
                        persist()
                        return self.session

                if self.session.total_probes_dispatched >= budget.max_probes:
                    self.session.status = "budget_exhausted"
                    persist()
                    return self.session

                if prior_dispatch and inter_probe_interval > 0:
                    self.sleeper(inter_probe_interval)
                    if budget.max_total_seconds is not None and (
                        elapsed_before_run + (time.monotonic() - start_time) >= budget.max_total_seconds
                    ):
                        self.session.status = "budget_exhausted"
                        persist()
                        return self.session

                # 5. Confirm the target still resolves to the approved address before
                # each additional side effect. Dispatch always uses the pinned IP.
                if probes_for_target:
                    try:
                        current_ip = self.dispatcher.resolve_target(target_host)
                    except Exception as err:
                        self.session.quarantined_targets.append(
                            TargetShiftQuarantine(
                                target_host=target_host,
                                original_ip=resolved_ip,
                                new_ip="unresolved",
                                reason=f"dns_resolution_failed: {err}",
                                timestamp_utc=utc_now(),
                            )
                        )
                        persist()
                        break
                    if current_ip != resolved_ip or (self.scope and not self._is_ip_in_scope(current_ip)):
                        self.session.quarantined_targets.append(
                            TargetShiftQuarantine(
                                target_host=target_host,
                                original_ip=resolved_ip,
                                new_ip=current_ip,
                                reason="dns_rebind_detected",
                                timestamp_utc=utc_now(),
                            )
                        )
                        persist()
                        break

                # DNS resolution can consume the remaining duration. Recheck
                # immediately before reserving a side effect and bound its
                # socket timeout by the time still available.
                probe_timeout = budget.timeout_seconds
                if budget.max_total_seconds is not None:
                    remaining_seconds = budget.max_total_seconds - (
                        elapsed_before_run + (time.monotonic() - start_time)
                    )
                    if remaining_seconds <= 0:
                        self.session.status = "budget_exhausted"
                        persist()
                        return self.session
                    probe_timeout = min(probe_timeout, remaining_seconds)

                # Reserve the attempt durably before the network side effect. A
                # crash or error leaves it pending for external reconciliation.
                self._validate_dns_probe_profile()
                self.session.pending_probe_keys.add(probe_key)
                self.session.total_probes_dispatched += 1
                prior_dispatch = True
                persist()
                try:
                    assessment = self.dispatcher.dispatch_probe(
                        target_host=target_host,
                        resolved_ip=resolved_ip,
                        port=port,
                        protocol=protocol,
                        timeout=probe_timeout,
                        vantage=self.session.vantage,
                    )
                    if (
                        not isinstance(assessment, ActiveServiceAssessment)
                        or assessment.target_host != target_host
                        or assessment.resolved_ip != resolved_ip
                        or assessment.port != port
                        or assessment.protocol != protocol
                        or assessment.vantage != self.session.vantage
                    ):
                        raise ActiveScanError("Probe result does not match its reserved target, port, and vantage")
                    self._validate_probe_evidence(assessment)
                except Exception:
                    self.session.status = "requires_reconciliation"
                    persist()
                    return self.session

                # Record assessment and update session side-effect ledger
                self.session.pending_probe_keys.remove(probe_key)
                self.session.completed_probe_keys.add(probe_key)
                self.session.assessments.append(assessment)
                self.session.total_side_effects += 1
                probes_for_target += 1
                persist()

        if self.session.status == "in_progress":
            self.session.status = "partial" if self.session.quarantined_targets else "completed"
        self.session.completed_at = utc_now()
        persist()
        return self.session


def compare_active_scans(baseline: ActiveScanSession, current: ActiveScanSession) -> ScanDelta:
    """Compare baseline scan against current scan to compute remediated and altered exposures."""

    def canonical_address(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value

    def identity(a: ActiveServiceAssessment) -> tuple[str, str, int, str, str]:
        return (
            canonical_address(a.target_host.lower()),
            a.protocol,
            a.port,
            canonical_address(a.resolved_ip),
            a.vantage,
        )

    def slot(a: ActiveServiceAssessment) -> tuple[str, str, int]:
        return (canonical_address(a.target_host.lower()), a.protocol, a.port)

    baseline_open: dict[tuple[str, str, int, str, str], ActiveServiceAssessment] = {}
    for a in baseline.assessments:
        if a.port_state == PortState.OPEN.value:
            baseline_open[identity(a)] = a

    current_open: dict[tuple[str, str, int, str, str], ActiveServiceAssessment] = {}
    current_all: dict[tuple[str, str, int, str, str], list[ActiveServiceAssessment]] = {}
    current_by_slot: dict[tuple[str, str, int], list[ActiveServiceAssessment]] = {}
    for a in current.assessments:
        key = identity(a)
        current_all.setdefault(key, []).append(a)
        current_by_slot.setdefault(slot(a), []).append(a)
        if a.port_state == PortState.OPEN.value:
            current_open[key] = a

    remediated: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    persistent: list[dict[str, Any]] = []
    new_exp: list[dict[str, Any]] = []
    fingerprint_changes: list[dict[str, Any]] = []

    for key, base_a in baseline_open.items():
        exact_retests = current_all.get(key, [])
        curr_a = current_open.get(key) or next(
            (a for a in exact_retests if a.port_state != PortState.CLOSED.value),
            exact_retests[-1] if exact_retests else None,
        )
        other_identity = (
            next(
                (a for a in current_by_slot.get(slot(base_a), []) if identity(a) != key),
                None,
            )
            if curr_a is None
            else None
        )
        if not curr_a or curr_a.port_state != PortState.OPEN.value:
            observed_retest = curr_a or other_identity
            item = {
                "target_host": base_a.target_host,
                "port": base_a.port,
                "protocol": base_a.protocol,
                "previous_state": base_a.port_state,
                "current_state": observed_retest.port_state if observed_retest else "not_probed",
                "service": base_a.inferred_fingerprint.service_name if base_a.inferred_fingerprint else "unknown",
                "previous_resolved_ip": base_a.resolved_ip,
                "current_resolved_ip": observed_retest.resolved_ip if observed_retest else None,
                "previous_vantage": base_a.vantage,
                "current_vantage": observed_retest.vantage if observed_retest else None,
            }
            # Only consistent refusals confirm that the previously open port is closed.
            # A different address or vantage cannot close the original exposure.
            if exact_retests and all(a.port_state == PortState.CLOSED.value for a in exact_retests):
                remediated.append(item)
            else:
                if other_identity:
                    item["reason"] = "identity_changed"
                elif curr_a:
                    item["reason"] = "inconclusive_retest"
                else:
                    item["reason"] = "not_probed"
                unverified.append(item)
        else:
            persistent.append(
                {
                    "target_host": curr_a.target_host,
                    "port": curr_a.port,
                    "protocol": curr_a.protocol,
                    "resolved_ip": curr_a.resolved_ip,
                    "vantage": curr_a.vantage,
                    "state": curr_a.port_state,
                    "service": curr_a.inferred_fingerprint.service_name if curr_a.inferred_fingerprint else "unknown",
                }
            )
            # Check for version / fingerprint changes
            base_fp = base_a.inferred_fingerprint
            curr_fp = curr_a.inferred_fingerprint
            if base_fp and curr_fp and (base_fp.product != curr_fp.product or base_fp.version != curr_fp.version):
                fingerprint_changes.append(
                    {
                        "target_host": curr_a.target_host,
                        "port": curr_a.port,
                        "protocol": curr_a.protocol,
                        "resolved_ip": curr_a.resolved_ip,
                        "vantage": curr_a.vantage,
                        "previous_product": base_fp.product,
                        "previous_version": base_fp.version,
                        "current_product": curr_fp.product,
                        "current_version": curr_fp.version,
                    }
                )

    for key, curr_a in current_open.items():
        if key not in baseline_open:
            new_exp.append(
                {
                    "target_host": curr_a.target_host,
                    "port": curr_a.port,
                    "protocol": curr_a.protocol,
                    "resolved_ip": curr_a.resolved_ip,
                    "vantage": curr_a.vantage,
                    "state": curr_a.port_state,
                    "service": curr_a.inferred_fingerprint.service_name if curr_a.inferred_fingerprint else "unknown",
                }
            )

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
        unverified_exposures=unverified,
    )
