"""Bounded, offline AI asset inventory contracts.

The inventory is an evidence projection, never a discovery or execution engine.
It deliberately accepts only a small, versioned record shape so imported traces,
prompts, inputs and outputs cannot enter the graph.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .canonical import EvidenceError, canonical, digest, timestamp

SCHEMA_VERSION = "cops.ai-inventory/v1"
COMPARISON_SCHEMA_VERSION = "cops.ai-inventory-comparison/v1"
REPORT_SCHEMA_VERSION = "cops.ai-inventory-report/v1"
MAX_DOCUMENT_BYTES = 512 * 1024
MAX_ASSETS = 1_000
MAX_RELATIONSHIPS = 5_000
MAX_UNKNOWNS = 1_000
MAX_IDENTITY_LINKS = 1_000
MAX_PATHS = 100
MAX_PATH_DEPTH = 8
MAX_PATH_EXPANSIONS = 10_000

ASSET_KINDS = frozenset({"agent", "agent_run", "model_endpoint", "mcp_server", "mcp_tool",
                         "retrieval_store", "memory_store", "cache_store", "service_identity", "document",
                         "destination"})
RELATIONSHIP_KINDS = frozenset({"authentication", "delegation", "reads", "writes",
                                "tool_invocation", "outbound_transfer", "parent_child"})
COMPLETENESS = frozenset({"complete", "partial", "unknown", "inaccessible"})
UNKNOWN_REASONS = frozenset({"missing", "stale", "opaque", "conflicting", "inaccessible"})
IDENTITY_LINK_REASONS = frozenset({"sponsor", "alias", "merge", "split"})


class InventoryError(EvidenceError):
    """A structured validation failure whose message is safe to surface."""


def _fail(code: str) -> None:
    raise InventoryError(code)


def _string(value: Any, code: str, *, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        _fail(code)
    return value


def _keys(value: Any, permitted: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) - permitted:
        _fail(code)
    return value


def _provenance(value: Any) -> dict[str, Any]:
    record = _keys(value, {"record_id", "reference", "observed_at", "completeness"},
                   "invalid_provenance")
    required = {"record_id", "reference", "completeness"}
    if not required <= set(record):
        _fail("invalid_provenance")
    result = {"record_id": _string(record["record_id"], "invalid_provenance"),
              "reference": _string(record["reference"], "invalid_provenance"),
              "completeness": _string(record["completeness"], "invalid_provenance")}
    if result["completeness"] not in COMPLETENESS:
        _fail("invalid_provenance")
    if "observed_at" in record:
        timestamp(record["observed_at"])
        result["observed_at"] = record["observed_at"]
    return result


def _source(value: Any) -> dict[str, Any]:
    source = _keys(value, {"provider", "tenant", "collection_id", "collected_at", "completeness",
                           "freshness_policy_seconds"}, "invalid_source")
    if {"provider", "tenant", "collection_id", "collected_at", "completeness"} - set(source):
        _fail("invalid_source")
    result = {key: _string(source[key], "invalid_source") for key in
              ("provider", "tenant", "collection_id", "collected_at", "completeness")}
    # These two values delimit the public namespace.  Rejecting the delimiter
    # keeps the namespace injective without encoding opaque provider names.
    if "/" in result["provider"] or "/" in result["tenant"]:
        _fail("invalid_source")
    timestamp(result["collected_at"])
    if result["completeness"] not in COMPLETENESS:
        _fail("invalid_source")
    if "freshness_policy_seconds" in source:
        policy = source["freshness_policy_seconds"]
        if type(policy) is not int or policy < 0:
            _fail("invalid_source")
        result["freshness_policy_seconds"] = policy
    return result


def _asset(value: Any, namespace: str) -> dict[str, Any]:
    item = _keys(value, {"id", "kind", "display_name", "external_id", "owner", "sensitivity", "trust",
                         "identity", "permissions", "scopes", "provenance"}, "invalid_asset")
    if {"id", "kind", "external_id", "owner", "sensitivity", "trust", "provenance"} - set(item):
        _fail("invalid_asset")
    kind = _string(item["kind"], "invalid_asset")
    if kind not in ASSET_KINDS:
        _fail("invalid_asset_kind")
    result = {"id": _string(item["id"], "invalid_asset"), "kind": kind,
              "external_id": _string(item["external_id"], "invalid_asset"),
              "owner": _string(item["owner"], "invalid_asset"),
              "sensitivity": _string(item["sensitivity"], "invalid_asset"),
              "trust": _string(item["trust"], "invalid_asset"),
              "provenance": _provenance(item["provenance"])}
    if result["sensitivity"] not in {"public", "internal", "confidential", "restricted", "unknown"}:
        _fail("invalid_asset")
    if result["trust"] not in {"untrusted", "trusted", "privileged", "unknown"}:
        _fail("invalid_asset")
    if "display_name" in item:
        result["display_name"] = _string(item["display_name"], "invalid_asset")
    if "identity" in item:
        identity = _keys(item["identity"], {"provider", "tenant", "kind", "id"}, "invalid_identity")
        if {"provider", "tenant", "kind", "id"} - set(identity):
            _fail("invalid_identity")
        result["identity"] = {key: _string(identity[key], "invalid_identity")
                              for key in ("provider", "tenant", "kind", "id")}
    for field in ("permissions", "scopes"):
        if field not in item:
            continue
        values = item[field]
        if not isinstance(values, list) or len(values) > 128:
            _fail("invalid_asset")
        normalized = [_string(value, "invalid_asset") for value in values]
        if len(set(normalized)) != len(normalized):
            _fail("invalid_asset")
        result[field] = sorted(normalized)
    result["qualified_id"] = f"{namespace}/{result['id']}"
    return result


def _identity(value: Any) -> dict[str, str]:
    identity = _keys(value, {"provider", "tenant", "kind", "id"}, "invalid_identity")
    if {"provider", "tenant", "kind", "id"} - set(identity):
        _fail("invalid_identity")
    return {key: _string(identity[key], "invalid_identity")
            for key in ("provider", "tenant", "kind", "id")}


def _identity_link(value: Any, namespace: str, assets: set[str]) -> dict[str, Any]:
    item = _keys(value, {"asset", "identity", "reason", "provenance"}, "invalid_identity_link")
    if {"asset", "identity", "reason", "provenance"} - set(item):
        _fail("invalid_identity_link")
    asset = _string(item["asset"], "invalid_identity_link")
    if asset not in assets:
        _fail("malformed_reference")
    reason = _string(item["reason"], "invalid_identity_link")
    if reason not in IDENTITY_LINK_REASONS:
        _fail("invalid_identity_link")
    return {"asset": f"{namespace}/{asset}", "identity": _identity(item["identity"]),
            "reason": reason, "provenance": _provenance(item["provenance"])}


def _relationship(value: Any, namespace: str, assets: set[str]) -> dict[str, Any]:
    item = _keys(value, {"id", "from", "to", "kind", "support", "provenance"}, "invalid_relationship")
    if {"id", "from", "to", "kind", "support", "provenance"} - set(item):
        _fail("invalid_relationship")
    kind = _string(item["kind"], "invalid_relationship")
    support = _string(item["support"], "invalid_relationship")
    if kind not in RELATIONSHIP_KINDS or support not in {"observed", "declared"}:
        _fail("invalid_relationship")
    source, target = _string(item["from"], "invalid_relationship"), _string(item["to"], "invalid_relationship")
    if source not in assets or target not in assets:
        _fail("malformed_reference")
    return {"id": _string(item["id"], "invalid_relationship"), "kind": kind, "support": support,
            "from": f"{namespace}/{source}", "to": f"{namespace}/{target}",
            "provenance": _provenance(item["provenance"])}


def import_inventory(document: Mapping[str, Any], *, engagement_id: str) -> dict[str, Any]:
    """Validate and normalize a complete inventory without retaining raw records.

    Caller-owned input is never mutated.  The returned snapshot is safe for
    comparison and reporting, but it is restricted to ``engagement_id``.
    """
    _string(engagement_id, "invalid_engagement")
    canonical(document, max_bytes=MAX_DOCUMENT_BYTES)
    root = _keys(document, {"schema_version", "source", "assets", "relationships", "unknowns",
                            "identity_links"},
                 "invalid_inventory")
    if root.get("schema_version") != SCHEMA_VERSION:
        _fail("unsupported_schema_version")
    if {"source", "assets", "relationships", "unknowns"} - set(root):
        _fail("invalid_inventory")
    source = _source(root["source"])
    if not all(isinstance(root[name], list) for name in ("assets", "relationships", "unknowns")) or (
            "identity_links" in root and not isinstance(root["identity_links"], list)):
        _fail("invalid_inventory")
    links = root.get("identity_links", [])
    if (len(root["assets"]) > MAX_ASSETS or len(root["relationships"]) > MAX_RELATIONSHIPS or
            len(root["unknowns"]) > MAX_UNKNOWNS or len(links) > MAX_IDENTITY_LINKS):
        _fail("document_limit")
    namespace = f"{source['provider']}/{source['tenant']}"
    assets = [_asset(item, namespace) for item in root["assets"]]
    seen: dict[str, dict[str, Any]] = {}
    for item in assets:
        prior = seen.get(item["id"])
        if prior is not None:
            _fail("duplicate_identity_conflict" if (prior["kind"], prior["external_id"], prior.get("identity")) !=
                  (item["kind"], item["external_id"], item.get("identity")) else "duplicate_identifier")
        seen[item["id"]] = item
    relationships = [_relationship(item, namespace, set(seen)) for item in root["relationships"]]
    relationship_ids = set()
    for item in relationships:
        if item["id"] in relationship_ids:
            _fail("duplicate_relationship")
        relationship_ids.add(item["id"])
    identity_links = [_identity_link(item, namespace, set(seen)) for item in links]
    link_keys = {(item["asset"], tuple(sorted(item["identity"].items()))) for item in identity_links}
    if len(link_keys) != len(identity_links):
        _fail("duplicate_identity_link")
    unknowns = []
    for item in root["unknowns"]:
        entry = _keys(item, {"subject", "reason"}, "invalid_unknown")
        if {"subject", "reason"} - set(entry):
            _fail("invalid_unknown")
        reason = _string(entry["reason"], "invalid_unknown")
        if reason not in UNKNOWN_REASONS:
            _fail("invalid_unknown")
        unknowns.append({"subject": _string(entry["subject"], "invalid_unknown"), "reason": reason})
    snapshot = {"schema_version": SCHEMA_VERSION, "engagement_id": engagement_id, "source": source,
                "namespace": namespace, "assets": sorted(assets, key=lambda item: item["qualified_id"]),
                "relationships": sorted(relationships, key=lambda item: item["id"]),
                "identity_links": sorted(identity_links,
                                         key=lambda item: (item["asset"], item["identity"]["provider"],
                                                           item["identity"]["tenant"], item["identity"]["id"])),
                "unknowns": sorted(unknowns, key=lambda item: (item["subject"], item["reason"]))}
    snapshot["snapshot_id"] = digest(snapshot, max_bytes=MAX_DOCUMENT_BYTES)
    return snapshot


class InventoryRegistry:
    """An engagement-isolated, in-memory registry for validated snapshots."""

    def __init__(self, engagement_id: str):
        self.engagement_id = _string(engagement_id, "invalid_engagement")
        self._snapshots: dict[str, dict[str, Any]] = {}

    def import_document(self, document: Mapping[str, Any]) -> dict[str, Any]:
        snapshot = import_inventory(document, engagement_id=self.engagement_id)
        self._snapshots.setdefault(snapshot["snapshot_id"], snapshot)
        return deepcopy(snapshot)

    def get(self, snapshot_id: str, *, engagement_id: str, namespace: str | None = None) -> dict[str, Any]:
        if engagement_id != self.engagement_id:
            _fail("restricted_reference")
        try:
            snapshot = self._snapshots[snapshot_id]
            if namespace is not None and namespace != snapshot["namespace"]:
                _fail("restricted_reference")
            return deepcopy(snapshot)
        except KeyError:
            _fail("unknown_snapshot")

    def report(self, snapshot_id: str, *, engagement_id: str, namespace: str | None = None) -> dict[str, Any]:
        return inventory_report(self.get(snapshot_id, engagement_id=engagement_id, namespace=namespace),
                                engagement_id=engagement_id, namespace=namespace)


def _validated_snapshot(snapshot: Mapping[str, Any], engagement_id: str,
                        namespace: str | None = None) -> dict[str, Any]:
    """Revalidate caller-supplied snapshots before report or comparison.

    Public imports return ordinary mappings for portability.  Rebuilding the
    canonical document prevents a caller from adding edges after validation.
    """
    if not isinstance(snapshot, Mapping) or snapshot.get("engagement_id") != engagement_id:
        _fail("restricted_reference")
    source = snapshot.get("source")
    if not isinstance(source, Mapping) or not isinstance(source.get("provider"), str) or not isinstance(source.get("tenant"), str):
        _fail("restricted_reference")
    prefix = f"{source['provider']}/{source['tenant']}/"

    def raw_id(value: Any) -> str:
        if not isinstance(value, str) or not value.startswith(prefix):
            _fail("restricted_reference")
        return value[len(prefix):]

    raw_assets = []
    for asset in snapshot.get("assets", []):
        if not isinstance(asset, Mapping) or not isinstance(asset.get("qualified_id"), str):
            _fail("restricted_reference")
        raw_assets.append({key: value for key, value in asset.items() if key != "qualified_id"})
    raw_relationships = []
    for relationship in snapshot.get("relationships", []):
        if not isinstance(relationship, Mapping):
            _fail("restricted_reference")
        item = dict(relationship)
        for key in ("from", "to"):
            value = item.get(key)
            item[key] = raw_id(value)
        raw_relationships.append(item)
    raw_links = []
    for link in snapshot.get("identity_links", []):
        if not isinstance(link, Mapping) or not isinstance(link.get("asset"), str):
            _fail("restricted_reference")
        item = dict(link)
        item["asset"] = raw_id(item["asset"])
        raw_links.append(item)
    rebuilt = import_inventory({"schema_version": snapshot.get("schema_version"), "source": source,
                                "assets": raw_assets, "relationships": raw_relationships,
                                "identity_links": raw_links, "unknowns": snapshot.get("unknowns")},
                               engagement_id=engagement_id)
    if snapshot.get("snapshot_id") != rebuilt["snapshot_id"]:
        _fail("restricted_reference")
    if namespace is not None and rebuilt["namespace"] != namespace:
        _fail("restricted_reference")
    return rebuilt


def compare_inventories(before: Mapping[str, Any], after: Mapping[str, Any], *, engagement_id: str) -> dict[str, Any]:
    """Return deterministic added, removed, changed and unknown inventory facts."""
    before = _validated_snapshot(before, engagement_id)
    after = _validated_snapshot(after, engagement_id)
    if before["namespace"] != after["namespace"]:
        _fail("namespace_mismatch")
    result: dict[str, Any] = {"schema_version": COMPARISON_SCHEMA_VERSION, "engagement_id": engagement_id,
                              "namespace": before["namespace"], "added": {}, "removed": {}, "changed": {},
                              "unknowns": sorted(after["unknowns"], key=lambda item: (item["subject"], item["reason"]))}
    for name, key in (("assets", "qualified_id"), ("relationships", "id")):
        old, new = ({item[key]: item for item in before[name]}, {item[key]: item for item in after[name]})
        result["added"][name] = [new[item] for item in sorted(new.keys() - old.keys())]
        result["removed"][name] = [old[item] for item in sorted(old.keys() - new.keys())]
        result["changed"][name] = [{"id": item, "before": old[item], "after": new[item]}
                                   for item in sorted(old.keys() & new.keys()) if old[item] != new[item]]
    before_assets = {item["qualified_id"]: item for item in before["assets"]}
    after_assets = {item["qualified_id"]: item for item in after["assets"]}
    for field in ("permissions", "scopes"):
        result[f"{field[:-1]}_changes"] = [
            {"id": item, "before": before_assets[item].get(field, []),
             "after": after_assets[item].get(field, [])}
            for item in sorted(before_assets.keys() & after_assets.keys())
            if before_assets[item].get(field, []) != after_assets[item].get(field, [])
        ]
    # A declared edge or a partial source must stay visibly uncertain in a diff;
    # comparison is not permitted to silently upgrade either into observation.
    result["uncertain_relationships"] = [item for item in after["relationships"]
                                         if item["support"] == "declared" or
                                         item["provenance"]["completeness"] != "complete"]
    result["identity_links"] = deepcopy(after["identity_links"])
    return result


def _trust_boundary_paths(snapshot: Mapping[str, Any], indexed: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return bounded, cycle-free paths from an agent or run to a destination."""
    outgoing: dict[str, list[Mapping[str, Any]]] = {}
    for edge in snapshot["relationships"]:
        outgoing.setdefault(edge["from"], []).append(edge)
    paths: list[dict[str, Any]] = []
    starts = [item for item in indexed.values() if item["kind"] in {"agent", "agent_run"}]
    expansions = 0
    for start in sorted(starts, key=lambda item: item["qualified_id"]):
        queue = [(start["qualified_id"], [], {start["qualified_id"]})]
        while queue and len(paths) < MAX_PATHS and expansions < MAX_PATH_EXPANSIONS:
            current, trail, visited = queue.pop(0)
            for edge in sorted(outgoing.get(current, []), key=lambda item: item["id"]):
                expansions += 1
                if expansions > MAX_PATH_EXPANSIONS:
                    break
                target = edge["to"]
                if target in visited:
                    continue
                next_trail = trail + [edge]
                if indexed[target]["kind"] == "destination":
                    paths.append({"from": {"id": start["qualified_id"], "kind": start["kind"]},
                                  "to": {"id": target, "kind": "destination"},
                                  "relationships": [{"id": item["id"], "kind": item["kind"],
                                                     "support": item["support"],
                                                     "completeness": item["provenance"]["completeness"]}
                                                    for item in next_trail]})
                elif len(next_trail) < MAX_PATH_DEPTH:
                    queue.append((target, next_trail, visited | {target}))
    return paths


def _privileged_document_paths(snapshot: Mapping[str, Any], indexed: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Find bounded document -> agent -> privileged-tool -> destination paths."""
    outgoing: dict[str, list[Mapping[str, Any]]] = {}
    for edge in snapshot["relationships"]:
        outgoing.setdefault(edge["from"], []).append(edge)
    paths, expansions = [], 0
    starts = [item for item in indexed.values() if item["kind"] == "document" and item["trust"] == "untrusted"]
    for start in sorted(starts, key=lambda item: item["qualified_id"]):
        queue = [(start["qualified_id"], [], {start["qualified_id"]})]
        while queue and len(paths) < MAX_PATHS and expansions < MAX_PATH_EXPANSIONS:
            current, trail, visited = queue.pop(0)
            for edge in sorted(outgoing.get(current, []), key=lambda item: item["id"]):
                expansions += 1
                if expansions > MAX_PATH_EXPANSIONS:
                    break
                target, next_trail = edge["to"], trail + [edge]
                if target in visited:
                    continue
                target_asset = indexed[target]
                agent_index = next((index for index, item in enumerate(next_trail)
                                    if indexed[item["to"]]["kind"] in {"agent", "agent_run"}), None)
                tool_index = next((index for index, item in enumerate(next_trail)
                                   if indexed[item["to"]]["kind"] == "mcp_tool" and
                                   indexed[item["to"]]["trust"] == "privileged"), None)
                if (target_asset["kind"] == "destination" and agent_index is not None and
                        tool_index is not None and agent_index < tool_index):
                    paths.append({"from": {"id": start["qualified_id"], "kind": "document", "trust": "untrusted"},
                                  "to": {"id": target, "kind": "destination", "trust": target_asset["trust"]},
                                  "relationships": [{"id": item["id"], "kind": item["kind"], "support": item["support"],
                                                     "completeness": item["provenance"]["completeness"]} for item in next_trail]})
                elif len(next_trail) < MAX_PATH_DEPTH:
                    queue.append((target, next_trail, visited | {target}))
    return paths


def inventory_report(snapshot: Mapping[str, Any], *, engagement_id: str,
                     namespace: str | None = None) -> dict[str, Any]:
    """Produce a restricted, deterministic summary; never expose source payloads."""
    snapshot = _validated_snapshot(snapshot, engagement_id, namespace)
    boundaries = []
    indexed = {item["qualified_id"]: item for item in snapshot["assets"]}
    for edge in snapshot["relationships"]:
        if edge["kind"] in {"authentication", "delegation", "tool_invocation", "outbound_transfer"}:
            boundaries.append({"relationship_id": edge["id"], "kind": edge["kind"], "support": edge["support"],
                               "from": {"id": edge["from"], "kind": indexed[edge["from"]]["kind"]},
                               "to": {"id": edge["to"], "kind": indexed[edge["to"]]["kind"]},
                               "completeness": edge["provenance"]["completeness"]})
    return {"schema_version": REPORT_SCHEMA_VERSION, "snapshot_id": snapshot["snapshot_id"],
            "restricted_reference": snapshot["snapshot_id"], "source": deepcopy(snapshot["source"]),
            "namespace": snapshot["namespace"], "counts": {"assets": len(snapshot["assets"]),
            "relationships": len(snapshot["relationships"]), "unknowns": len(snapshot["unknowns"])},
            "trust_boundaries": boundaries, "trust_boundary_paths": _trust_boundary_paths(snapshot, indexed),
            "privileged_document_paths": _privileged_document_paths(snapshot, indexed),
            "identity_links": deepcopy(snapshot["identity_links"]),
            "unknowns": deepcopy(snapshot["unknowns"])}


def adapt_entra_service_principals(export: Mapping[str, Any], *, tenant: str, collected_at: str,
                                   collection_id: str = "service-principals") -> dict[str, Any]:
    """Map an offline Microsoft Graph service-principal export into this contract.

    This adapter reads the supplied export only.  It does not call Microsoft
    Graph, discover assets, invoke tools, or keep unselected export fields.
    """
    _keys(export, {"value"}, "invalid_entra_export")
    if not isinstance(export.get("value"), list):
        _fail("invalid_entra_export")
    assets = []
    for item in export["value"]:
        record = _keys(item, {"id", "appId", "displayName"}, "invalid_entra_export")
        if {"id", "appId"} - set(record):
            _fail("invalid_entra_export")
        identifier = _string(record["id"], "invalid_entra_export")
        assets.append({"id": f"service-principal/{identifier}", "kind": "service_identity",
                       "display_name": record.get("displayName", identifier), "external_id": identifier,
                       "owner": "unknown", "sensitivity": "restricted", "trust": "privileged",
                       "identity": {"provider": "entra", "tenant": tenant, "kind": "service_principal", "id": identifier},
                       "provenance": {"record_id": identifier, "reference": f"entra-service-principal/{identifier}",
                                      "observed_at": collected_at, "completeness": "partial"}})
    return {"schema_version": SCHEMA_VERSION,
            "source": {"provider": "entra", "tenant": tenant, "collection_id": collection_id,
                       "collected_at": collected_at, "completeness": "partial"},
            "assets": assets, "relationships": [], "unknowns": [{"subject": "service-principal ownership", "reason": "opaque"}]}
