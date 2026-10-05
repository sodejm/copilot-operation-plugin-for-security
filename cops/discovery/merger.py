"""Asset deduplication and multi-source evidence provenance merger."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import DiscoveredAsset, DiscoveryInventory, EvidenceProvenance


def merge_two_assets(existing: DiscoveredAsset, incoming: DiscoveredAsset) -> DiscoveredAsset:
    """Merge two asset observations of the same entity while preserving all evidence provenance."""
    # Deduplicate provenance by (source_id, sha256, raw_record_ref)
    prov_map: dict[tuple[str, str, str | None], EvidenceProvenance] = {}
    for p in existing.provenance + incoming.provenance:
        key = (p.source_id, p.sha256, p.raw_record_ref)
        if key not in prov_map:
            prov_map[key] = p

    merged_prov = list(prov_map.values())

    # Merge attributes and detect conflicting ownership
    merged_attrs = dict(existing.attributes)

    existing_owner = existing.attributes.get("owner")
    incoming_owner = incoming.attributes.get("owner")

    if (
        existing_owner
        and incoming_owner
        and str(existing_owner).strip().lower() != str(incoming_owner).strip().lower()
    ):
        merged_attrs["conflicting_ownership"] = True
        merged_attrs["conflicting_owners"] = sorted(list({str(existing_owner), str(incoming_owner)}))

    # Also detect conflicting tenant IDs
    existing_tenant = existing.attributes.get("tenant_id")
    incoming_tenant = incoming.attributes.get("tenant_id")
    if (
        existing_tenant
        and incoming_tenant
        and str(existing_tenant).strip().lower() != str(incoming_tenant).strip().lower()
    ):
        merged_attrs["conflicting_ownership"] = True

    # Fill in any missing attributes from incoming
    for k, v in incoming.attributes.items():
        if k not in merged_attrs or merged_attrs[k] is None:
            merged_attrs[k] = v

    # Stale record propagation
    if existing.attributes.get("stale") or incoming.attributes.get("stale"):
        merged_attrs["stale"] = True

    # Merge quarantine reasons
    reasons = sorted(list(set(existing.quarantine_reasons + incoming.quarantine_reasons)))
    if merged_attrs.get("conflicting_ownership") and "conflicting_ownership" not in reasons:
        reasons.append("conflicting_ownership")
        reasons.sort()

    status = "quarantined" if reasons else (existing.status if existing.status == incoming.status else "quarantined")

    return DiscoveredAsset(
        asset_id=existing.asset_id,
        asset_type=existing.asset_type,
        identifier=existing.identifier,
        attributes=merged_attrs,
        provenance=merged_prov,
        status=status,
        quarantine_reasons=reasons,
    )


def merge_inventories(
    *inventories: DiscoveryInventory | list[DiscoveredAsset],
) -> DiscoveryInventory:
    """Merge multiple discovery inventories or asset lists, deduplicating identical entities."""
    grouped: dict[tuple[str, str], DiscoveredAsset] = {}

    for item in inventories:
        asset_list = item.assets if isinstance(item, DiscoveryInventory) else item
        for asset in asset_list:
            key = (asset.asset_type, asset.identifier.lower().strip())
            if key not in grouped:
                grouped[key] = asset
            else:
                grouped[key] = merge_two_assets(grouped[key], asset)

    merged_assets = list(grouped.values())

    summary = {
        "total_assets": len(merged_assets),
        "verified_in_scope": sum(1 for a in merged_assets if a.status == "verified_in_scope"),
        "quarantined": sum(1 for a in merged_assets if a.status == "quarantined"),
        "excluded": sum(1 for a in merged_assets if a.status == "excluded"),
        "by_type": {
            "dns": sum(1 for a in merged_assets if a.asset_type == "dns"),
            "certificate": sum(1 for a in merged_assets if a.asset_type == "certificate"),
            "ip_address": sum(1 for a in merged_assets if a.asset_type == "ip_address"),
            "endpoint": sum(1 for a in merged_assets if a.asset_type == "endpoint"),
            "cloud_resource": sum(1 for a in merged_assets if a.asset_type == "cloud_resource"),
        },
    }

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return DiscoveryInventory(
        timestamp=now_iso,
        assets=merged_assets,
        summary=summary,
    )
