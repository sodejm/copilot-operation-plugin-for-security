"""Cross-field evidence checks for otherwise schema-valid offline artifacts."""

from __future__ import annotations

from typing import Any

from .models import EntraError


def _require_fresh_sources(
    source_ids: list[str], coverage: dict[str, dict[str, Any]], claim: str
) -> None:
    if not source_ids:
        raise EntraError(f"{claim} has no evidence sources")
    for source_id in source_ids:
        if coverage.get(source_id, {}).get("status") != "fresh":
            raise EntraError(f"{claim} cites non-fresh source '{source_id}'")


def validate_graph_artifact(document: dict[str, Any]) -> None:
    """Check fresh node and edge claims against coverage and endpoint status.

    Validate the document against graph.schema.json first for field shapes.
    """
    coverage = document["source_coverage"]
    nodes = {node["node_id"]: node for node in document["nodes"]}
    for node in document["nodes"]:
        if node["evidence_status"] == "fresh" and node["node_type"] != "tenant":
            _require_fresh_sources(
                [node["evidence_source"]], coverage, f"node '{node['node_id']}'"
            )
    for edge in document["edges"]:
        if edge["evidence_status"] != "fresh":
            continue
        claim = f"edge '{edge['edge_id']}'"
        _require_fresh_sources(edge["evidence_sources"], coverage, claim)
        for node_id in (edge["source_id"], edge["target_id"]):
            if nodes.get(node_id, {}).get("evidence_status") != "fresh":
                raise EntraError(f"{claim} cites non-fresh endpoint '{node_id}'")


def validate_report_artifact(document: dict[str, Any]) -> None:
    """Check each current hypothesis against its cited source coverage.

    Validate the document against report.schema.json first for field shapes.
    """
    coverage = document["source_coverage"]
    for hypothesis in document["hypotheses"]:
        if hypothesis["evidence_status"] != "fresh":
            raise EntraError(
                f"hypothesis '{hypothesis['hypothesis_id']}' is not fresh"
            )
        _require_fresh_sources(
            hypothesis["evidence_sources"],
            coverage,
            f"hypothesis '{hypothesis['hypothesis_id']}'",
        )
