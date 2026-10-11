"""Validate opaque AD graph exports and trace bounded, evidence-linked paths."""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}\Z")
KINDS = {"principal", "group", "host", "domain", "forest", "privilege"}
RELATIONS = {"member_of", "privilege", "trust", "session"}
SOURCES = {"directory", "host"}
MAX_BYTES = 1_048_576
MAX_NODES = 500
MAX_EDGES = 2_000
MAX_QUERIES = 20
MAX_DEPTH = 6
MAX_PATHS = 20
MAX_EXPANSIONS = 10_000


class InventoryError(ValueError):
    """Stable validation error for a rejected local export."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _object(value: object, keys: set[str], required: set[str]) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - keys:
        raise InventoryError("invalid_structure")
    return value


def _id(value: object) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise InventoryError("invalid_id")
    return value


def _items(value: object, limit: int) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise InventoryError("invalid_size")
    return value


def _unique(items: list, name: str) -> dict[str, dict]:
    result = {}
    for item in items:
        if not isinstance(item, dict):
            raise InventoryError("invalid_structure")
        identifier = _id(item.get("id"))
        if identifier in result:
            raise InventoryError(f"conflicting_{name}")
        result[identifier] = item
    return result


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InventoryError("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InventoryError("invalid_timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise InventoryError("invalid_timestamp")
    return parsed


def load_export(path: Path) -> dict:
    """Load a bounded regular JSON file without following a path supplied by its data."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise InventoryError("invalid_file")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InventoryError("invalid_file")
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InventoryError("invalid_json") from error


def _validate(export: object) -> tuple[dict, dict, dict, list, list, dict]:
    data = _object(export, {"schema_version", "scope", "collections", "nodes", "edges", "queries"},
                   {"schema_version", "scope", "collections", "nodes", "edges", "queries"})
    if data["schema_version"] != "1.0":
        raise InventoryError("unsupported_schema")
    scope = _object(data["scope"], {"forests", "domains", "hosts"}, {"forests", "domains", "hosts"})
    forests = _items(scope["forests"], 20)
    if not forests or len({_id(v) for v in forests}) != len(forests):
        raise InventoryError("invalid_scope")
    domains = _unique(_items(scope["domains"], 100), "domain")
    hosts = _unique(_items(scope["hosts"], 500), "host")
    for domain in domains.values():
        _object(domain, {"id", "forest"}, {"id", "forest"})
        if _id(domain["forest"]) not in forests:
            raise InventoryError("out_of_scope")
    for host in hosts.values():
        _object(host, {"id", "domain"}, {"id", "domain"})
        if _id(host["domain"]) not in domains:
            raise InventoryError("out_of_scope")
    collections = _unique(_items(data["collections"], 500), "collection")
    for collection in collections.values():
        _object(collection, {"id", "source", "forest", "domain", "host", "collected_at", "completeness"},
                {"id", "source", "forest", "collected_at", "completeness"})
        if not isinstance(collection["source"], str) or collection["source"] not in SOURCES or (
            not isinstance(collection["completeness"], str)
            or collection["completeness"] not in {"complete", "partial"}
        ):
            raise InventoryError("invalid_collection")
        if _id(collection["forest"]) not in forests:
            raise InventoryError("out_of_scope")
        domain_id = collection.get("domain")
        if domain_id is not None and (_id(domain_id) not in domains or domains[domain_id]["forest"] != collection["forest"]):
            raise InventoryError("out_of_scope")
        host_id = collection.get("host")
        if host_id is not None and (_id(host_id) not in hosts or hosts[host_id]["domain"] != domain_id):
            raise InventoryError("out_of_scope")
        if collection["source"] == "host" and host_id is None:
            raise InventoryError("invalid_collection")
        if collection["source"] == "directory" and host_id is not None:
            raise InventoryError("invalid_collection")
        _time(collection["collected_at"])
    nodes = _unique(_items(data["nodes"], MAX_NODES), "identity")
    for node in nodes.values():
        _object(node, {"id", "kind", "forest", "domain", "protected"},
                {"id", "kind", "forest", "protected"})
        if not isinstance(node["kind"], str) or node["kind"] not in KINDS or type(node["protected"]) is not bool:
            raise InventoryError("invalid_node")
        if _id(node["forest"]) not in forests:
            raise InventoryError("out_of_scope")
        if node["kind"] == "forest":
            if node["id"] != node["forest"] or "domain" in node:
                raise InventoryError("invalid_node")
        else:
            domain_id = node.get("domain")
            if _id(domain_id) not in domains or domains[domain_id]["forest"] != node["forest"]:
                raise InventoryError("out_of_scope")
            if node["kind"] == "domain" and node["id"] != domain_id:
                raise InventoryError("invalid_node")
            if node["kind"] == "host" and (node["id"] not in hosts or hosts[node["id"]]["domain"] != domain_id):
                raise InventoryError("out_of_scope")
    edges = _items(data["edges"], MAX_EDGES)
    _unique(edges, "edge")
    for edge in edges:
        _object(edge, {"id", "source", "target", "kind", "collector_id", "collected_at", "completeness", "support"},
                {"id", "source", "target", "kind", "collector_id", "collected_at", "completeness", "support"})
        source, target, collector_id = _id(edge["source"]), _id(edge["target"]), _id(edge["collector_id"])
        if source not in nodes or target not in nodes or collector_id not in collections:
            raise InventoryError("missing_reference")
        if not isinstance(edge["kind"], str) or edge["kind"] not in RELATIONS or (
            not isinstance(edge["support"], str) or edge["support"] not in {"observed", "inferred"}
        ):
            raise InventoryError("invalid_edge")
        collector = collections[collector_id]
        if not isinstance(edge["completeness"], str) or edge["completeness"] != collector["completeness"]:
            raise InventoryError("conflicting_completeness")
        if _time(edge["collected_at"]) > _time(collector["collected_at"]):
            raise InventoryError("invalid_timestamp")
        if collector["forest"] != nodes[source]["forest"]:
            raise InventoryError("collector_scope_mismatch")
        if collector.get("domain") is not None and collector["domain"] != nodes[source].get("domain"):
            raise InventoryError("collector_scope_mismatch")
        if collector["source"] == "host" and edge["kind"] != "session":
            raise InventoryError("collector_scope_mismatch")
        if collector["source"] == "host" and collector["host"] not in {source, target}:
            raise InventoryError("collector_scope_mismatch")
        cross_forest = nodes[source]["forest"] != nodes[target]["forest"]
        if cross_forest and (edge["kind"] != "trust" or nodes[source]["kind"] != "domain"
                             or nodes[target]["kind"] != "domain"):
            raise InventoryError("unapproved_forest_boundary")
        if edge["kind"] == "trust" and (nodes[source]["kind"] != "domain" or nodes[target]["kind"] != "domain"):
            raise InventoryError("invalid_edge")
    queries = _items(data["queries"], MAX_QUERIES)
    for query in queries:
        _object(query, {"start", "goal"}, {"start", "goal"})
        if _id(query["start"]) not in nodes or _id(query["goal"]) not in nodes:
            raise InventoryError("missing_reference")
    return scope, domains, hosts, edges, queries, {"nodes": nodes, "collections": collections}


def _coverage(scope: dict, collections: dict) -> dict:
    result = {"forests": {}, "hosts": {}}
    for forest in sorted(scope["forests"]):
        relevant = [c for c in collections.values() if c["source"] == "directory" and c["forest"] == forest]
        domains = [d["id"] for d in scope["domains"] if d["forest"] == forest]
        forest_wide = any(c.get("domain") is None and c["completeness"] == "complete" for c in relevant)
        domains_covered = all(any(c.get("domain") == domain and c["completeness"] == "complete"
                                  for c in relevant) for domain in domains)
        if not relevant:
            result["forests"][forest] = "unknown"
        elif any(c["completeness"] == "partial" for c in relevant) or not (forest_wide or domains_covered):
            result["forests"][forest] = "partial"
        else:
            result["forests"][forest] = "complete"
    for host in sorted(h["id"] for h in scope["hosts"]):
        relevant = [c for c in collections.values() if c.get("host") == host]
        result["hosts"][host] = "unknown" if not relevant else (
            "partial" if any(c["completeness"] == "partial" for c in relevant) else "complete")
    return result


def analyze(export: object) -> dict:
    """Return a deterministic candidate-path report; never assert live reachability."""
    scope, _, _, edges, queries, references = _validate(export)
    nodes, collections = references["nodes"], references["collections"]
    adjacency = defaultdict(list)
    for edge in sorted(edges, key=lambda item: item["id"]):
        adjacency[edge["source"]].append(edge)
    results = []
    for query in queries:
        found = []
        queue = deque([(query["start"], [], {query["start"]})])
        expansions = 0
        depth_limited = False
        while queue and len(found) < MAX_PATHS and expansions < MAX_EXPANSIONS:
            current, path, visited = queue.popleft()
            if current == query["goal"] and path:
                flags = set()
                for edge in path:
                    if edge["support"] == "inferred":
                        flags.add("inferred_relationship")
                    if edge["completeness"] == "partial":
                        flags.add("partial_collection")
                    if edge["kind"] == "trust":
                        flags.add("trust_boundary")
                    if nodes[edge["source"]]["protected"] or nodes[edge["target"]]["protected"]:
                        flags.add("protected_identity")
                found.append({"status": "candidate_requires_validation", "flags": sorted(flags),
                              "edges": [{key: edge[key] for key in ("id", "source", "target", "kind", "collector_id",
                                                                        "collected_at", "completeness", "support")}
                                        for edge in path]})
                continue
            if len(path) >= MAX_DEPTH:
                depth_limited |= bool(adjacency[current])
                continue
            for edge in adjacency[current]:
                expansions += 1
                if edge["target"] not in visited:
                    queue.append((edge["target"], path + [edge], visited | {edge["target"]}))
                if expansions >= MAX_EXPANSIONS:
                    break
        results.append({"start": query["start"], "goal": query["goal"],
                        "status": "candidate_paths" if found else "not_found_in_collected_graph",
                        "paths": found, "truncated": bool(queue) or expansions >= MAX_EXPANSIONS or depth_limited})
    return {"schema_version": "1.0", "assessment": "offline_structural_only",
            "coverage": _coverage(scope, collections), "queries": results}
