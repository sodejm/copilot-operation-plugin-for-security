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
    evidence_source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "display_name": self.display_name,
            "tenant_id": self.tenant_id,
            "properties": self.properties,
            "evidence_source": self.evidence_source,
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
    evidence_sources: tuple[str, ...] = ()

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
            "evidence_sources": list(self.evidence_sources),
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
    source_coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    assessed_at: str | None = None
    max_age_hours: int = 24

    def node_evidence(self, node: IdentityNode) -> tuple[str, list[str]]:
        """Return whether the source supporting a node is current and complete."""
        if not self.source_coverage:
            return "unknown", ["missing_coverage"]
        if node.node_type == "tenant":
            return "fresh", []
        if not node.evidence_source:
            return "unknown", ["unattributed_source"]
        coverage = self.source_coverage.get(node.evidence_source)
        if coverage is None:
            return "unknown", ["not_listed"]
        if coverage["status"] != "fresh":
            return "unknown", [str(coverage["reason"])]
        return "fresh", []

    def edge_evidence(self, edge: IdentityEdge) -> tuple[str, list[str]]:
        """Evaluate every source and endpoint needed for an entitlement path."""
        if not self.source_coverage:
            return "unknown", ["missing_coverage"]
        reasons: list[str] = []
        if not edge.evidence_sources:
            reasons.append("unattributed_source")
        for source_id in edge.evidence_sources:
            coverage = self.source_coverage.get(source_id)
            if coverage is None:
                reasons.append("not_listed")
            elif coverage["status"] != "fresh":
                reasons.append(str(coverage["reason"]))
        for node_id in (edge.source_id, edge.target_id):
            node = self.nodes.get(node_id)
            if node is None:
                reasons.append("missing_endpoint")
            else:
                reasons.extend(self.node_evidence(node)[1])
        unique_reasons = list(dict.fromkeys(reasons))
        return ("unknown", unique_reasons) if unique_reasons else ("fresh", [])

    def to_dict(self) -> dict[str, Any]:
        from .validation import validate_export_metadata, validate_graph_artifact

        validate_export_metadata(self)
        nodes = []
        for node in sorted(self.nodes.values(), key=lambda n: n.node_id):
            status, reasons = self.node_evidence(node)
            nodes.append({**node.to_dict(), "evidence_status": status, "evidence_reasons": reasons})
        edges = []
        for edge in sorted(self.edges, key=lambda e: e.edge_id):
            status, reasons = self.edge_evidence(edge)
            edges.append({**edge.to_dict(), "evidence_status": status, "evidence_reasons": reasons})
        document = {
            "schema_version": "entra.identity-graph/v2",
            "tenant_id": self.tenant_id,
            "assessed_at": self.assessed_at,
            "max_age_hours": self.max_age_hours,
            "source_coverage": self.source_coverage,
            "nodes": nodes,
            "edges": edges,
        }
        validate_graph_artifact(document)
        return document
