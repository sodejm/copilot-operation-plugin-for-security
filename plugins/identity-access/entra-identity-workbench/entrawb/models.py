"""Immutable typed models for Entra ID and AI Agent identity graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class EntraError(ValueError):
    """Raised when Entra identity ingestion, graph validation, or analysis fails."""


@dataclass(frozen=True)
class IdentityNode:
    """A typed entity within the Entra identity graph."""

    node_id: str
    node_type: str
    display_name: str
    tenant_id: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "display_name": self.display_name,
            "tenant_id": self.tenant_id,
            "properties": self.properties,
        }


@dataclass(frozen=True)
class IdentityEdge:
    """A typed relationship or privilege assignment between identity nodes."""

    edge_id: str
    source_id: str
    target_id: str
    relation: str
    grant_type: str
    scope: str
    provenance: str
    pim_state: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "grant_type": self.grant_type,
            "scope": self.scope,
            "provenance": self.provenance,
            "pim_state": self.pim_state,
        }


@dataclass(frozen=True)
class ReviewHypothesis:
    """A prioritized review finding with supporting edges and missing evidence."""

    hypothesis_id: str
    category: str
    severity: str
    principal_id: str
    principal_name: str
    principal_type: str
    description: str
    supporting_edges: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "category": self.category,
            "severity": self.severity,
            "principal_id": self.principal_id,
            "principal_name": self.principal_name,
            "principal_type": self.principal_type,
            "description": self.description,
            "supporting_edges": list(self.supporting_edges),
            "missing_evidence": list(self.missing_evidence),
            "recommended_action": self.recommended_action,
        }


@dataclass(frozen=True)
class IdentityGraph:
    """A normalized Entra and Azure RBAC identity graph snapshot."""

    tenant_id: str
    nodes: dict[str, IdentityNode]
    edges: list[IdentityEdge]
    sources: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "entra.identity-graph/v1",
            "tenant_id": self.tenant_id,
            "nodes": [node.to_dict() for node in sorted(self.nodes.values(), key=lambda n: n.node_id)],
            "edges": [edge.to_dict() for edge in sorted(self.edges, key=lambda e: e.edge_id)],
        }
