"""COPS passive and active asset discovery, service identification, and scope reconciliation runtime."""

from __future__ import annotations

from .active_models import (
    ActiveScanSession,
    ActiveServiceAssessment,
    ConfidenceLevel,
    InferredFingerprint,
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
from .active_scanner import (
    ActiveScanError,
    ActiveScanner,
    OfflineSyntheticDispatcher,
    ProbeDispatcher,
    ScopeViolationError,
    StandardSocketDispatcher,
    compare_active_scans,
)
from .cli import build_discovery_parser, command_discovery
from .fingerprinter import infer_service_fingerprint
from .importer import import_masscan_json, import_nmap_xml
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
    "ActiveScanError",
    "ActiveScanSession",
    "ActiveScanner",
    "ActiveServiceAssessment",
    "AssetType",
    "ConfidenceLevel",
    "DiscoveredAsset",
    "DiscoveryInventory",
    "EvidenceProvenance",
    "InferredFingerprint",
    "ObservedConfiguration",
    "ObservedTLS",
    "OfflineSyntheticDispatcher",
    "PortState",
    "ProbeDispatcher",
    "Protocol",
    "QuarantineReason",
    "ReconciliationStatus",
    "ScanBudget",
    "ScanDelta",
    "ScanVantage",
    "ScopeViolationError",
    "ServiceReachability",
    "StandardSocketDispatcher",
    "TargetShiftQuarantine",
    "build_discovery_parser",
    "command_discovery",
    "compare_active_scans",
    "import_masscan_json",
    "import_nmap_xml",
    "infer_service_fingerprint",
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
