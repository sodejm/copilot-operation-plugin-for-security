"""Execution-time scope and egress guard for COPS security operations.

Validates that network destinations, IP addresses, subnets, domains, and cloud/cluster resources
strictly reside within authorized engagement boundaries, mitigating DNS rebinding, alternate IP encodings,
cloud metadata access, and unauthorized egress pivots.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


class ScopeViolationError(ValueError):
    """Raised when an operation attempts to target an unauthorized destination or egress boundary."""


METADATA_ADDRESSES: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS/GCP/Azure IMDS
        "fd00:ec2::254",  # AWS IPv6 IMDS
        "100.100.100.200",  # Alibaba Cloud IMDS
    }
)


def parse_ip_or_network(
    target: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Safely parse an IP address or CIDR network string, returning None if not an IP."""
    target = target.strip()
    try:
        if "/" in target:
            return ipaddress.ip_network(target, strict=False)
        return ipaddress.ip_address(target)
    except ValueError:
        return None


def is_ip_in_network(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, net: ipaddress.IPv4Network | ipaddress.IPv6Network
) -> bool:
    """Check if an IP address is contained within a network, matching IP versions."""
    if ip.version != net.version:
        return False
    return ip in net


@dataclass
class ScopeDefinition:
    """Normalized engagement scope boundary definition."""

    included_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    included_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(default_factory=set)
    included_domains: set[str] = field(default_factory=set)
    included_cloud_resources: set[str] = field(default_factory=set)

    excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    excluded_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(default_factory=set)
    excluded_domains: set[str] = field(default_factory=set)
    excluded_cloud_resources: set[str] = field(default_factory=set)

    block_cloud_metadata: bool = True
    block_loopback_unless_explicit: bool = True
    egress_allowed: bool = False

    @classmethod
    def from_engagement_scope(
        cls,
        scope_dict: dict[str, Any],
        *,
        egress_allowed: bool = False,
    ) -> ScopeDefinition:
        """Parse an engagement scope dictionary into typed ScopeDefinition."""
        included = scope_dict.get("included_targets", [])
        excluded = scope_dict.get("excluded_targets", [])

        inc_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        inc_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        inc_doms: set[str] = set()
        inc_res: set[str] = set()

        for item in included:
            parsed = parse_ip_or_network(item)
            if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                inc_nets.append(parsed)
            elif isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                inc_ips.add(parsed)
            elif "/" in item or ":" in item:  # e.g. cloud resource arn:aws:... or sub/namespace
                inc_res.add(item.lower())
            else:
                inc_doms.add(item.lower().lstrip("."))

        exc_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        exc_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        exc_doms: set[str] = set()
        exc_res: set[str] = set()

        for item in excluded:
            parsed = parse_ip_or_network(item)
            if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                exc_nets.append(parsed)
            elif isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                exc_ips.add(parsed)
            elif "/" in item or ":" in item:
                exc_res.add(item.lower())
            else:
                exc_doms.add(item.lower().lstrip("."))

        return cls(
            included_networks=inc_nets,
            included_ips=inc_ips,
            included_domains=inc_doms,
            included_cloud_resources=inc_res,
            excluded_networks=exc_nets,
            excluded_ips=exc_ips,
            excluded_domains=exc_doms,
            excluded_cloud_resources=exc_res,
            egress_allowed=egress_allowed,
        )


class ScopeGuard:
    """Execution-time scope and egress enforcer."""

    def __init__(
        self,
        scope: ScopeDefinition,
        *,
        resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self.scope = scope
        self.resolver = resolver or self._default_resolver

    def _default_resolver(self, host: str) -> list[str]:
        """Resolve a host to IP addresses using standard socket getaddrinfo."""
        try:
            results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = []
            for item in results:
                ip_str = item[4][0]
                if ip_str not in ips:
                    ips.append(ip_str)
            return ips
        except socket.gaierror:
            return []

    def check_destination(self, destination: str) -> None:
        """Validate destination (IP, hostname, URL, or resource identifier) against scope.

        Raises ScopeViolationError if destination is out of scope or explicitly excluded.
        """
        dest_clean = destination.strip()
        if not dest_clean:
            raise ScopeViolationError("Empty destination target")

        # Strip URL scheme and path if present
        if "://" in dest_clean:
            parsed_url = urlparse(dest_clean)
            host = parsed_url.hostname or dest_clean
        elif ":" in dest_clean and not dest_clean.startswith("[") and "/" not in dest_clean:
            # host:port check
            parts = dest_clean.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                host = parts[0]
            else:
                host = dest_clean
        else:
            host = dest_clean

        # Check cloud resource ID match with identifier boundary awareness
        def _matches_resource(t: str, prefix: str) -> bool:
            tl = t.lower()
            pl = prefix.lower()
            if tl == pl:
                return True
            if tl.startswith(pl) and len(tl) > len(pl):
                return tl[len(pl)] in ("/", ":", ".", "-")
            return False

        if any(_matches_resource(host, res) for res in self.scope.excluded_cloud_resources):
            raise ScopeViolationError(f"Target '{destination}' is in explicitly excluded cloud resources")

        if any(_matches_resource(host, res) for res in self.scope.included_cloud_resources):
            return  # Explicitly in-scope cloud resource

        # Check if direct IP address or CIDR network
        parsed_ip = parse_ip_or_network(host)
        if isinstance(parsed_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            self._validate_ip(parsed_ip, original_target=destination)
            return
        elif isinstance(parsed_ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            self._validate_network(parsed_ip, original_target=destination)
            return

        # It is a hostname / domain
        domain_clean = host.lower().lstrip(".")

        # Explicit exclusions always take precedence, including when DNS is
        # unavailable or returns an empty answer for an otherwise included name.
        if domain_clean in self.scope.excluded_domains or any(
            domain_clean.endswith("." + exc) for exc in self.scope.excluded_domains
        ):
            raise ScopeViolationError(f"Domain '{domain_clean}' is in explicitly excluded scope")

        # Resolve hostname to check underlying IP addresses (anti-DNS rebinding / bypass)
        resolved_ips = self.resolver(domain_clean)
        if not resolved_ips:
            # If domain cannot be resolved, check if domain name itself is explicitly included
            if domain_clean in self.scope.included_domains or any(
                domain_clean.endswith("." + inc) for inc in self.scope.included_domains
            ):
                return
            raise ScopeViolationError(f"Domain '{domain_clean}' is neither resolvable nor in allowed domain scope")
        self.check_resolved_destination(domain_clean, resolved_ips)

    def check_resolved_destination(self, host: str, addresses: list[str] | tuple[str, ...]) -> None:
        """Validate a hostname and the exact address set selected by an execution mediator.

        The mediator owns resolution so it can bind validation, connection, and a
        second resolution to the same request. This method deliberately performs
        no additional lookup that could validate one DNS answer and connect to a
        different one.
        """
        domain_clean = host.lower().rstrip(".").lstrip(".")
        if not domain_clean:
            raise ScopeViolationError("Empty destination hostname")
        literal = parse_ip_or_network(domain_clean)
        if not isinstance(literal, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and (
            domain_clean in self.scope.excluded_domains
            or any(domain_clean.endswith("." + exc) for exc in self.scope.excluded_domains)
        ):
            raise ScopeViolationError(f"Domain '{domain_clean}' is in explicitly excluded scope")
        if not addresses:
            raise ScopeViolationError(f"Domain '{domain_clean}' did not resolve to an address")

        resolved_addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for ip_str in addresses:
            parsed = parse_ip_or_network(ip_str)
            if not isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                raise ScopeViolationError(f"Resolver returned a non-address value for '{domain_clean}'")
            if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
                parsed = parsed.ipv4_mapped
            self._validate_ip(parsed, original_target=f"{domain_clean} -> {ip_str}")
            resolved_addresses.add(parsed)

        if isinstance(literal, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if isinstance(literal, ipaddress.IPv6Address) and literal.ipv4_mapped:
                literal = literal.ipv4_mapped
            if resolved_addresses != {literal}:
                raise ScopeViolationError("IP literal resolution changed the requested destination")
            return

        if not (
            domain_clean in self.scope.included_domains
            or any(domain_clean.endswith("." + included) for included in self.scope.included_domains)
        ):
            raise ScopeViolationError(f"Domain '{domain_clean}' is outside the included domain scope")

    def _validate_network(
        self,
        net: ipaddress.IPv4Network | ipaddress.IPv6Network,
        *,
        original_target: str,
    ) -> None:
        """Validate a CIDR network destination against metadata, exclusions, and inclusions."""
        # 1. Cloud metadata guard
        for meta_ip_str in METADATA_ADDRESSES:
            try:
                meta_ip = ipaddress.ip_address(meta_ip_str)
                if meta_ip.version == net.version and meta_ip in net:
                    raise ScopeViolationError(
                        f"Network '{net}' covers cloud metadata service '{meta_ip_str}' ({original_target})"
                    )
            except ValueError:
                pass

        # 2. Loopback guard
        if self.scope.block_loopback_unless_explicit and net.is_loopback:
            if not any(
                net.subnet_of(inc_net) for inc_net in self.scope.included_networks if inc_net.version == net.version
            ):
                raise ScopeViolationError(
                    f"Access to loopback network '{net}' is blocked without explicit inclusion ({original_target})"
                )

        # 3. Explicit exclusion check
        for exc_ip in self.scope.excluded_ips:
            if exc_ip.version == net.version and exc_ip in net:
                raise ScopeViolationError(f"Network '{net}' covers excluded IP '{exc_ip}' ({original_target})")
        for exc_net in self.scope.excluded_networks:
            if net.overlaps(exc_net):
                raise ScopeViolationError(
                    f"Network '{net}' overlaps with excluded subnet '{exc_net}' ({original_target})"
                )

        # 4. Inclusion check
        for inc_net in self.scope.included_networks:
            if net.subnet_of(inc_net):
                return

        raise ScopeViolationError(f"Destination network '{net}' ({original_target}) is NOT within authorized scope")

    def _validate_ip(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        *,
        original_target: str,
    ) -> None:
        """Validate an individual IP address against metadata, exclusions, and inclusions."""
        # Normalize IPv4-mapped IPv6 address (e.g. ::ffff:169.254.169.254)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        ip_str = str(ip)

        # 1. Cloud metadata guard (SSRF / credential exfiltration protection)
        if self.scope.block_cloud_metadata and ip_str in METADATA_ADDRESSES:
            raise ScopeViolationError(
                f"Access to cloud metadata service '{ip_str}' is strictly blocked ({original_target})"
            )

        # 2. Loopback guard
        if self.scope.block_loopback_unless_explicit and ip.is_loopback:
            if ip not in self.scope.included_ips and not any(
                is_ip_in_network(ip, net) for net in self.scope.included_networks
            ):
                raise ScopeViolationError(
                    f"Access to loopback address '{ip_str}' is blocked without explicit inclusion ({original_target})"
                )

        # 3. Explicit exclusion check
        if ip in self.scope.excluded_ips:
            raise ScopeViolationError(f"IP '{ip_str}' is in explicitly excluded targets ({original_target})")
        for exc_net in self.scope.excluded_networks:
            if is_ip_in_network(ip, exc_net):
                raise ScopeViolationError(f"IP '{ip_str}' falls within excluded subnet '{exc_net}' ({original_target})")

        # 4. Inclusion check
        if ip in self.scope.included_ips:
            return
        for inc_net in self.scope.included_networks:
            if is_ip_in_network(ip, inc_net):
                return

        # Not included in scope
        raise ScopeViolationError(f"Destination IP '{ip_str}' ({original_target}) is NOT within authorized scope")
