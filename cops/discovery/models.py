"""Data models for passive asset discovery, evidence provenance, and quarantine reconciliation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal


class AssetType(str, Enum):
    DNS = "dns"
    CERTIFICATE = "certificate"
    IP_ADDRESS = "ip_address"
    ENDPOINT = "endpoint"
    CLOUD_RESOURCE = "cloud_resource"


class ReconciliationStatus(str, Enum):
    VERIFIED_IN_SCOPE = "verified_in_scope"
    QUARANTINED = "quarantined"
    EXCLUDED = "excluded"


class QuarantineReason(str, Enum):
    UNCERTAIN_OWNERSHIP = "uncertain_ownership"
    CONFLICTING_OWNERSHIP = "conflicting_ownership"
    STALE_RECORD = "stale_record"
    MISSING_PROVENANCE = "missing_provenance"
    OUTSIDE_SCOPE = "outside_scope"
    EXPLICITLY_EXCLUDED = "explicitly_excluded"


@dataclass
class EvidenceProvenance:
    """Cryptographic and contextual provenance binding for an asset."""

    source_id: str
    source_type: str
    sha256: str
    timestamp: str
    path_or_uri: str
    raw_record_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceProvenance:
        return cls(
            source_id=str(data.get("source_id", "")),
            source_type=str(data.get("source_type", "")),
            sha256=str(data.get("sha256", "")),
            timestamp=str(data.get("timestamp", "")),
            path_or_uri=str(data.get("path_or_uri", "")),
            raw_record_ref=data.get("raw_record_ref"),
        )


@dataclass
class DiscoveredAsset:
    """Normalized asset record with provenance and scope reconciliation state."""

    asset_id: str
    asset_type: Literal["dns", "certificate", "ip_address", "endpoint", "cloud_resource"]
    identifier: str
    attributes: dict[str, Any] = field(default_factory=dict)
    provenance: list[EvidenceProvenance] = field(default_factory=list)
    status: Literal["verified_in_scope", "quarantined", "excluded"] = "quarantined"
    quarantine_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "identifier": self.identifier,
            "attributes": self.attributes,
            "provenance": [p.to_dict() for p in self.provenance],
            "status": self.status,
            "quarantine_reasons": self.quarantine_reasons,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveredAsset:
        return cls(
            asset_id=str(data.get("asset_id", "")),
            asset_type=data.get("asset_type", "dns"),
            identifier=str(data.get("identifier", "")),
            attributes=dict(data.get("attributes", {})),
            provenance=[
                EvidenceProvenance.from_dict(p)
                for p in data.get("provenance", [])
            ],
            status=data.get("status", "quarantined"),
            quarantine_reasons=list(data.get("quarantine_reasons", [])),
        )


@dataclass
class DiscoveryInventory:
    """Collection of discovered assets with summary analytics."""

    timestamp: str
    assets: list[DiscoveredAsset] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "assets": [a.to_dict() for a in self.assets],
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveryInventory:
        return cls(
            timestamp=str(data.get("timestamp", "")),
            assets=[
                DiscoveredAsset.from_dict(a)
                for a in data.get("assets", [])
            ],
            summary=dict(data.get("summary", {})),
        )
