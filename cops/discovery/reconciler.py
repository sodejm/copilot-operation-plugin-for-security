"""Ownership reconciliation and quarantine evaluation against authorized engagement scope."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from .models import DiscoveredAsset, DiscoveryInventory


def _matches_domain_pattern(host: str, pattern: str) -> bool:
    """Check exact match or subdomain match."""
    h = host.lower().rstrip(".")
    p = pattern.lower().rstrip(".")
    return h == p or h.endswith("." + p)


def _ip_in_ranges(ip_str: str, ranges: list[str]) -> bool:
    """Check if IP address falls within any CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net_str in ranges:
            try:
                if ip in ipaddress.ip_network(net_str, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        return False
    return False


def reconcile_asset(asset: DiscoveredAsset, scope: dict[str, Any]) -> DiscoveredAsset:
    """Reconcile an individual asset against engagement scope boundaries.

    Ensures that uncertain, stale, conflicting, or unverified assets are quarantined
    so discovery cannot expand the engagement without operator authorization.
    """
    quarantine_reasons: list[str] = list(asset.quarantine_reasons)
    status = "verified_in_scope"

    # 1. Provenance Integrity Check
    if not asset.provenance:
        quarantine_reasons.append("missing_provenance")
    else:
        for p in asset.provenance:
            if not p.sha256 or not p.source_id or not p.path_or_uri:
                quarantine_reasons.append("missing_provenance")
                break

    attrs = asset.attributes

    # 2. Conflicting Ownership Check
    if attrs.get("conflicting_ownership"):
        quarantine_reasons.append("conflicting_ownership")

    # 3. Stale Record Check (dangling DNS pointer, expired cert, or explicit stale flag)
    if attrs.get("stale") is True:
        quarantine_reasons.append("stale_record")
    if attrs.get("target_status") in ("nxdomain", "dangling", "unallocated"):
        quarantine_reasons.append("stale_record")
    if attrs.get("not_after"):
        try:
            not_after_dt = datetime.fromisoformat(str(attrs["not_after"]).replace("Z", "+00:00"))
            if not_after_dt < datetime.now(UTC):
                quarantine_reasons.append("stale_record")
        except (ValueError, TypeError):
            pass

    # 4. Scope Exclusions Check
    exclusions = scope.get("exclusions", {})
    excluded_domains = exclusions.get("domains", [])
    excluded_ips = exclusions.get("ip_ranges", [])
    excluded_tenants = exclusions.get("tenant_ids", [])

    is_excluded = False
    # Check IP exclusion
    asset_ip = attrs.get("ip") or (asset.identifier if asset.asset_type == "ip_address" else None)
    if asset_ip and _ip_in_ranges(asset_ip, excluded_ips):
        is_excluded = True

    # Check Domain exclusion
    asset_domain = attrs.get("domain") or (asset.identifier if asset.asset_type in ("dns", "certificate") else None)
    if not asset_domain and asset.asset_type == "endpoint":
        asset_domain = attrs.get("host")

    if asset_domain and any(_matches_domain_pattern(asset_domain, d) for d in excluded_domains):
        is_excluded = True

    # Check Tenant exclusion
    if attrs.get("tenant_id") and attrs["tenant_id"] in excluded_tenants:
        is_excluded = True

    if is_excluded:
        quarantine_reasons.append("explicitly_excluded")
        return DiscoveredAsset(
            asset_id=asset.asset_id,
            asset_type=asset.asset_type,
            identifier=asset.identifier,
            attributes=asset.attributes,
            provenance=asset.provenance,
            status="excluded",
            quarantine_reasons=sorted(set(quarantine_reasons)),
        )

    # 5. In-Scope Target Boundary Validation
    approved_domains = scope.get("domains", []) or scope.get("targets", [])
    approved_ips = scope.get("ip_ranges", [])

    in_scope_boundary = False
    if asset_domain and any(_matches_domain_pattern(asset_domain, d) for d in approved_domains if isinstance(d, str) and not d.startswith("1") and not d.startswith("2")):
        in_scope_boundary = True
    elif asset_ip and _ip_in_ranges(asset_ip, approved_ips):
        in_scope_boundary = True
    elif attrs.get("tenant_id") and attrs["tenant_id"] in scope.get("tenant_ids", []):
        in_scope_boundary = True

    if not in_scope_boundary:
        quarantine_reasons.append("outside_scope")

    # 6. Ownership Certainty Check
    owner = attrs.get("owner")
    if not owner or owner in ("unknown", "unassigned", "unclaimed"):
        quarantine_reasons.append("uncertain_ownership")

    # Final status evaluation
    clean_reasons = sorted(set(quarantine_reasons))
    if clean_reasons:
        status = "quarantined"
    else:
        status = "verified_in_scope"

    return DiscoveredAsset(
        asset_id=asset.asset_id,
        asset_type=asset.asset_type,
        identifier=asset.identifier,
        attributes=asset.attributes,
        provenance=asset.provenance,
        status=status,
        quarantine_reasons=clean_reasons,
    )


def reconcile_inventory(
    assets: list[DiscoveredAsset],
    scope: dict[str, Any],
) -> DiscoveryInventory:
    """Reconcile full list of assets and produce a classified DiscoveryInventory."""
    reconciled_assets = [reconcile_asset(a, scope) for a in assets]

    summary = {
        "total_assets": len(reconciled_assets),
        "verified_in_scope": sum(1 for a in reconciled_assets if a.status == "verified_in_scope"),
        "quarantined": sum(1 for a in reconciled_assets if a.status == "quarantined"),
        "excluded": sum(1 for a in reconciled_assets if a.status == "excluded"),
        "by_type": {
            "dns": sum(1 for a in reconciled_assets if a.asset_type == "dns"),
            "certificate": sum(1 for a in reconciled_assets if a.asset_type == "certificate"),
            "ip_address": sum(1 for a in reconciled_assets if a.asset_type == "ip_address"),
            "endpoint": sum(1 for a in reconciled_assets if a.asset_type == "endpoint"),
            "cloud_resource": sum(1 for a in reconciled_assets if a.asset_type == "cloud_resource"),
        },
    }

    now_iso = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return DiscoveryInventory(
        timestamp=now_iso,
        assets=reconciled_assets,
        summary=summary,
    )
