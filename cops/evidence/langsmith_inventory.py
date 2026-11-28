"""Offline LangSmith query-runs adapter for the AI inventory registry.

Only the documented selected-field response projection is accepted. Raw trace
content has no representation in the normalized inventory document.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .ai_inventory import InventoryError, InventoryRegistry, inventory_report
from .canonical import EvidenceError, canonical, timestamp
from .export_policy import ExportBoundary, ExportRefused, ExportSink, SanitizedExport

SCHEMA_VERSION = "cops.langsmith-query-runs/v2"
MAX_DOCUMENT_BYTES = 512 * 1024
# Each accepted run produces at least two unknown facts and tools produce a
# third. This bound keeps every valid projection below the registry's limit.
MAX_RUNS = 240

_ROOT_KEYS = {"schema_version", "source", "response"}
_SOURCE_KEYS = {"tenant", "collection_id", "exported_at", "reference"}
_RESPONSE_KEYS = {"items", "next_cursor"}
_RUN_KEYS = {"id", "name", "run_type", "start_time", "parent_run_ids", "trace_id", "project_id"}
_RUN_TYPES = frozenset({"CHAIN", "LLM", "EMBEDDING", "RETRIEVER", "TOOL"})
_SEMANTIC_EDGE_KINDS = {
    "LLM": "delegation",
    "EMBEDDING": "delegation",
    "TOOL": "tool_invocation",
}


def _fail(code: str) -> None:
    raise InventoryError(code)


def _keys(value: Any, permitted: set[str], required: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) - permitted or required - set(value):
        _fail(code)
    return value


def _string(value: Any, code: str, *, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        _fail(code)
    return value


def _uuid(value: Any, code: str) -> str:
    text = _string(value, code, limit=36)
    try:
        parsed = str(UUID(text))
    except (ValueError, AttributeError):
        _fail(code)
    if parsed != text:
        _fail(code)
    return text


def _timestamp(value: Any, code: str) -> str:
    try:
        timestamp(value)
    except EvidenceError:
        _fail(code)
    return value


def _normalize_run(value: Any) -> dict[str, Any]:
    run = _keys(value, _RUN_KEYS, _RUN_KEYS, "invalid_langsmith_run")
    run_type = _string(run["run_type"], "invalid_langsmith_run_type", limit=32)
    if run_type not in _RUN_TYPES:
        _fail("unsupported_langsmith_run_type")
    parents = run["parent_run_ids"]
    if not isinstance(parents, list) or len(parents) > 32:
        _fail("invalid_langsmith_parent_ids")
    parent_ids = [_uuid(parent, "invalid_langsmith_parent_id") for parent in parents]
    identifier = _uuid(run["id"], "invalid_langsmith_run_id")
    if len(parent_ids) != len(set(parent_ids)) or identifier in parent_ids:
        _fail("invalid_langsmith_parent_ids")
    return {
        "id": identifier,
        # Names are validated for the pinned API projection but are intentionally
        # not copied into the inventory because user-defined names may contain PII.
        "name": _string(run["name"], "invalid_langsmith_run_name"),
        "run_type": run_type,
        "start_time": _timestamp(run["start_time"], "invalid_langsmith_start_time"),
        "parent_run_ids": parent_ids,
        "trace_id": _uuid(run["trace_id"], "invalid_langsmith_trace_id"),
        "project_id": _uuid(run["project_id"], "invalid_langsmith_project_id"),
    }


def _validate_parent_graph(runs: Mapping[str, Mapping[str, Any]]) -> None:
    # Follow only the immediate observed parent. Missing ancestors end a path;
    # they never cause an invented placeholder node or edge. Detect cycles
    # before comparing lineage so a cyclic response has one stable failure.
    for start in runs:
        current = start
        visited: set[str] = set()
        while current in runs:
            if current in visited:
                _fail("langsmith_parent_cycle")
            visited.add(current)
            parents = runs[current]["parent_run_ids"]
            if not parents:
                break
            current = parents[-1]

    for run in runs.values():
        if not run["parent_run_ids"]:
            continue
        parent = runs.get(run["parent_run_ids"][-1])
        if parent is not None:
            if (parent["trace_id"], parent["project_id"]) != (run["trace_id"], run["project_id"]):
                _fail("langsmith_parent_context_conflict")
            expected_lineage = [*parent["parent_run_ids"], parent["id"]]
            if run["parent_run_ids"] != expected_lineage:
                _fail("langsmith_parent_lineage_conflict")


def _provenance(run: Mapping[str, Any], reference: str, completeness: str) -> dict[str, str]:
    return {
        "record_id": run["id"],
        "reference": reference,
        "observed_at": run["start_time"],
        "completeness": completeness,
    }


def _asset_id(run: Mapping[str, Any]) -> str:
    """Keep the selected provider operation type without asserting a resource."""
    return f"run/{run['run_type'].lower()}/{run['id']}"


def adapt_langsmith_query_runs(document: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one pinned LangSmith v2 query-runs response into inventory v1."""
    try:
        canonical(document, max_bytes=MAX_DOCUMENT_BYTES)
    except EvidenceError as error:
        _fail("langsmith_document_limit" if error.code == "payload_limit" else "invalid_langsmith_document")
    root = _keys(document, _ROOT_KEYS, _ROOT_KEYS, "invalid_langsmith_document")
    if root["schema_version"] != SCHEMA_VERSION:
        _fail("unsupported_langsmith_schema_version")

    source = _keys(root["source"], _SOURCE_KEYS, _SOURCE_KEYS, "invalid_langsmith_source")
    tenant = _string(source["tenant"], "invalid_langsmith_tenant")
    if "/" in tenant:
        _fail("invalid_langsmith_tenant")
    collection_id = _string(source["collection_id"], "invalid_langsmith_collection_id")
    exported_at = _timestamp(source["exported_at"], "invalid_langsmith_exported_at")
    reference = _string(source["reference"], "invalid_langsmith_reference")

    response = _keys(root["response"], _RESPONSE_KEYS, _RESPONSE_KEYS, "invalid_langsmith_response")
    items = response["items"]
    if not isinstance(items, list):
        _fail("invalid_langsmith_response")
    if len(items) > MAX_RUNS:
        _fail("langsmith_run_limit")
    next_cursor = response["next_cursor"]
    if next_cursor is not None:
        _string(next_cursor, "invalid_langsmith_next_cursor", limit=2_048)
    completeness = "partial" if next_cursor is not None else "complete"

    runs: dict[str, dict[str, Any]] = {}
    for value in items:
        run = _normalize_run(value)
        prior = runs.get(run["id"])
        if prior is not None and prior != run:
            _fail("duplicate_langsmith_run_conflict")
        runs.setdefault(run["id"], run)
    _validate_parent_graph(runs)

    assets: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    unknowns: list[dict[str, str]] = []
    for run in sorted(runs.values(), key=lambda item: item["id"]):
        asset_id = _asset_id(run)
        assets.append(
            {
                "id": asset_id,
                "kind": "agent_run",
                "external_id": run["id"],
                "owner": "unknown",
                "sensitivity": "restricted",
                "trust": "unknown",
                "identity": {
                    "provider": "langsmith",
                    "tenant": tenant,
                    "kind": f"{run['run_type'].lower()}_run",
                    "id": run["id"],
                },
                "provenance": _provenance(run, reference, completeness),
            }
        )
        unknowns.extend(
            [
                {"subject": f"{asset_id} owner", "reason": "missing"},
                {"subject": f"{asset_id} permissions", "reason": "missing"},
            ]
        )
        if run["run_type"] == "TOOL":
            unknowns.append({"subject": f"{asset_id} effect", "reason": "missing"})

        if not run["parent_run_ids"]:
            continue
        parent_id = run["parent_run_ids"][-1]
        parent = runs.get(parent_id)
        if parent is None:
            unknowns.append({"subject": f"{asset_id} parent/{parent_id}", "reason": "missing"})
            continue
        parent_asset_id = _asset_id(parent)
        relationship_provenance = _provenance(run, reference, completeness)
        relationships.append(
            {
                "id": f"edge/{parent_id}/{run['id']}/parent-child",
                "from": parent_asset_id,
                "to": asset_id,
                "kind": "parent_child",
                "support": "observed",
                "provenance": relationship_provenance,
            }
        )
        semantic_kind = _SEMANTIC_EDGE_KINDS.get(run["run_type"])
        if semantic_kind is not None:
            relationships.append(
                {
                    "id": f"edge/{parent_id}/{run['id']}/{semantic_kind}",
                    "from": parent_asset_id,
                    "to": asset_id,
                    "kind": semantic_kind,
                    "support": "observed",
                    "provenance": relationship_provenance,
                }
            )

    if completeness == "partial":
        unknowns.append({"subject": "response pagination", "reason": "missing"})
    return {
        "schema_version": "cops.ai-inventory/v1",
        "source": {
            "provider": "langsmith",
            "tenant": tenant,
            "collection_id": collection_id,
            "collected_at": exported_at,
            "completeness": completeness,
        },
        "assets": assets,
        "relationships": relationships,
        "identity_links": [],
        "unknowns": unknowns,
    }


def import_langsmith_query_runs(document: Mapping[str, Any], *, registry: InventoryRegistry) -> dict[str, Any]:
    """Import a LangSmith projection into a caller-owned engagement registry."""
    if not isinstance(registry, InventoryRegistry):
        _fail("invalid_inventory_registry")
    return registry.import_document(adapt_langsmith_query_runs(document))


def export_langsmith_inventory(
    snapshot: Mapping[str, Any],
    *,
    engagement_id: str,
    boundary: ExportBoundary,
    sink: ExportSink,
    pseudonym_scope: str,
    namespace: str | None = None,
) -> SanitizedExport:
    """Send a bounded report through the concrete privacy boundary."""
    if not isinstance(boundary, ExportBoundary):
        _fail("invalid_export_boundary")
    try:
        destination = sink.descriptor.destination
    except (AttributeError, TypeError):
        raise ExportRefused("adapter_destination_mismatch") from None
    if destination != "report":
        raise ExportRefused("adapter_destination_mismatch")
    report = inventory_report(snapshot, engagement_id=engagement_id, namespace=namespace)
    return boundary.export(
        sink,
        report,
        restricted_evidence_reference=report["restricted_reference"],
        pseudonym_scope=pseudonym_scope,
    )
