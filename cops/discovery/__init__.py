"""COPS passive asset discovery, evidence provenance, and scope reconciliation runtime."""

from __future__ import annotations

from .cli import build_discovery_parser, command_discovery
from .merger import merge_inventories, merge_two_assets
from .models import (
    AssetType,
    DiscoveredAsset,
    DiscoveryInventory,
    EvidenceProvenance,
    QuarantineReason,
    ReconciliationStatus,
)
from .normalizers import (
    normalize_certificate_record,
    normalize_cloud_export,
    normalize_dns_record,
    normalize_endpoint_record,
    normalize_ip_record,
)
from .reconciler import reconcile_asset, reconcile_inventory

__all__ = [
    "AssetType",
    "DiscoveredAsset",
    "DiscoveryInventory",
    "EvidenceProvenance",
    "QuarantineReason",
    "ReconciliationStatus",
    "build_discovery_parser",
    "command_discovery",
    "merge_inventories",
    "merge_two_assets",
    "normalize_certificate_record",
    "normalize_cloud_export",
    "normalize_dns_record",
    "normalize_endpoint_record",
    "normalize_ip_record",
    "reconcile_asset",
    "reconcile_inventory",
]
