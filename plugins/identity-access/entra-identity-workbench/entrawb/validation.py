"""Cross-field evidence checks for otherwise schema-valid offline artifacts."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import EntraError, IdentityGraph


_COVERAGE_FIELDS = {"status", "reason", "path", "sha256", "completeness", "exported_at"}
_UNKNOWN_REASONS = {"not_listed", "missing_file", "incomplete", "invalid_timestamp", "future_timestamp", "stale"}
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _timestamp(value: Any, *, utc_only: bool = False) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value) or (utc_only and not value.endswith("Z")):
        raise EntraError("Export requires an RFC 3339 assessment time in UTC and valid source timestamps")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EntraError("Export has an invalid assessment or source timestamp") from exc
    return parsed.astimezone(UTC)


def validate_export_metadata(graph: IdentityGraph) -> None:
    """Fail closed before exporting a graph without complete v2 freshness metadata."""
    from .graph import SOURCE_IDS

    assessed = _timestamp(graph.assessed_at, utc_only=True)
    if type(graph.max_age_hours) is not int or graph.max_age_hours != 24:
        raise EntraError("Export requires a 24-hour freshness limit")
    coverage = graph.source_coverage
    if not isinstance(coverage, dict) or set(coverage) != set(SOURCE_IDS):
        raise EntraError("Export requires source coverage for every Entra source")
    for source_id, item in coverage.items():
        if not isinstance(item, dict) or set(item) != _COVERAGE_FIELDS:
            raise EntraError(f"Export requires complete source coverage for '{source_id}'")
        status = item["status"]
        if status == "fresh":
            if (item["reason"] is not None or not isinstance(item["path"], str) or not item["path"]
                or not isinstance(item["sha256"], str) or not _SHA256.fullmatch(item["sha256"])
                or item["completeness"] != "full"):
                raise EntraError(f"Fresh source '{source_id}' has incomplete provenance")
            exported = _timestamp(item["exported_at"])
            if exported > assessed or assessed - exported > timedelta(hours=24):
                raise EntraError(f"Fresh source '{source_id}' is outside the assessment window")
        elif status == "unknown":
            if item["reason"] not in _UNKNOWN_REASONS:
                raise EntraError(f"Unknown source '{source_id}' requires a valid reason")
            for key in ("path", "sha256", "exported_at"):
                if item[key] is not None and not isinstance(item[key], str):
                    raise EntraError(f"Unknown source '{source_id}' has an invalid {key}")
            if item["completeness"] not in (None, "full", "partial", "unknown"):
                raise EntraError(f"Unknown source '{source_id}' has invalid completeness")
        else:
            raise EntraError(f"Source '{source_id}' requires fresh or unknown status")


def _require_fresh_sources(source_ids: list[str], coverage: dict[str, dict[str, Any]], claim: str) -> None:
    if not source_ids:
        raise EntraError(f"{claim} has no evidence sources")
    for source_id in source_ids:
        if coverage.get(source_id, {}).get("status") != "fresh":
            raise EntraError(f"{claim} cites non-fresh source '{source_id}'")


def validate_graph_artifact(document: dict[str, Any]) -> None:
    """Check fresh node and edge claims against coverage and endpoint status.

    Validate the document against graph.v2.schema.json first for field shapes.
    """
    coverage = document["source_coverage"]
    nodes = {node["node_id"]: node for node in document["nodes"]}
    for node in document["nodes"]:
        if node["evidence_status"] == "fresh" and node["node_type"] != "tenant":
            _require_fresh_sources([node["evidence_source"]], coverage, f"node '{node['node_id']}'")
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

    Validate the document against report.v2.schema.json first for field shapes.
    """
    coverage = document["source_coverage"]
    for hypothesis in document["hypotheses"]:
        if hypothesis["evidence_status"] != "fresh":
            raise EntraError(f"hypothesis '{hypothesis['hypothesis_id']}' is not fresh")
        _require_fresh_sources(
            hypothesis["evidence_sources"],
            coverage,
            f"hypothesis '{hypothesis['hypothesis_id']}'",
        )
