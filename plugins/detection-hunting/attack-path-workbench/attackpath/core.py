"""Deterministic evidence, graph, path, and report gates for local exports."""

from __future__ import annotations

import hashlib
import json
import copy
from collections import defaultdict
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path
from typing import Any

from . import VERSION


class GateError(ValueError):
    """A blocking deterministic gate error with a field or record location."""


SCHEMA = "attackpath.input/v1"
PROFILE = "illustrative_canonical/v1"
NODE_TYPES = {"asset", "data", "service", "identity"}
RELATIONS = {
    "reachable_from": {"network_reachability"},
    "permission_to_act": {"read", "modify", "disrupt", "control"},
    "accesses_data": {"read", "modify"},
    "service_depends_on": {"none"},
}
CAPABILITIES = {"finding_on_asset", "network_reachability", "read", "modify", "disrupt", "control"}
CONFIDENCE_ORDER = {"undetermined": 0, "low": 1, "medium": 2, "high": 3}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_keys(obj: Any, required: set[str], optional: set[str], where: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise GateError(f"{where}: expected object")
    missing, unknown = required - obj.keys(), obj.keys() - required - optional
    if missing or unknown:
        raise GateError(f"{where}: missing={sorted(missing)}, unknown={sorted(unknown)}")
    return obj


def identifier(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise GateError(f"{where}: expected nonempty identifier of at most 256 characters")
    return value


def utc(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateError(f"{where}: expected UTC timestamp ending Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"{where}: invalid UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise GateError(f"{where}: expected UTC timestamp")
    return value


def utc_time(value: Any, where: str) -> datetime:
    return datetime.fromisoformat(utc(value, where).replace("Z", "+00:00"))


def parse_json(data: bytes, path: Path) -> Any:
    try:
        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise GateError(f"{path}: duplicate JSON key {key!r}")
                result[key] = value
            return result
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{path}: cannot read JSON: {exc}") from exc


def load_json(path: Path) -> Any:
    try:
        return parse_json(path.read_bytes(), path)
    except OSError as exc:
        raise GateError(f"{path}: cannot read JSON: {exc}") from exc


def validate_input(value: Any, base: Path) -> tuple[dict[str, Any], list[tuple[dict[str, Any], Path, Any]]]:
    obj = exact_keys(value, {"schema_version", "sources", "context"}, set(), "input")
    if obj["schema_version"] != SCHEMA:
        raise GateError("input.schema_version: unsupported")
    if not isinstance(obj["sources"], list) or not obj["sources"]:
        raise GateError("input.sources: expected nonempty list")
    context = exact_keys(obj["context"], {"crown_jewels", "scope", "impact_profile_id"}, {"time_window"}, "context")
    identifier(context["scope"], "context.scope")
    if context["impact_profile_id"] is not None:
        raise GateError("context.impact_profile_id: approved impact profiles are not installed")
    if not isinstance(context["crown_jewels"], list) or not context["crown_jewels"]:
        raise GateError("context.crown_jewels: expected nonempty list")
    crown_ids: set[str] = set()
    for i, item in enumerate(context["crown_jewels"]):
        cj = exact_keys(item, {"asset_ref", "name", "priority", "business_service", "cia_objectives"}, set(), f"crown_jewels[{i}]")
        asset_ref = identifier(cj["asset_ref"], f"crown_jewels[{i}].asset_ref")
        if asset_ref in crown_ids:
            raise GateError(f"crown_jewels[{i}]: duplicate asset_ref")
        crown_ids.add(asset_ref)
        identifier(cj["name"], f"crown_jewels[{i}].name")
        if cj["priority"] is not None and (type(cj["priority"]) is not int or cj["priority"] < 0):
            raise GateError(f"crown_jewels[{i}].priority: expected nonnegative integer or null")
        if cj["business_service"] is not None:
            identifier(cj["business_service"], f"crown_jewels[{i}].business_service")
        if cj["cia_objectives"] is not None:
            raise GateError(f"crown_jewels[{i}].cia_objectives: rating rubric pending")
    window = context.get("time_window")
    if window is not None:
        exact_keys(window, {"start", "end"}, set(), "context.time_window")
        if utc_time(window["start"], "time_window.start") > utc_time(window["end"], "time_window.end"):
            raise GateError("context.time_window: start after end")
    sources = []
    seen: set[str] = set()
    snapshot_time: str | None = None
    for i, source in enumerate(obj["sources"]):
        src = exact_keys(source, {"source_id", "kind", "path", "sha256", "exported_at", "scope", "profile_id", "coverage"}, {"record_count"}, f"sources[{i}]")
        source_id = identifier(src["source_id"], f"sources[{i}].source_id")
        if source_id in seen:
            raise GateError(f"sources[{i}]: duplicate source_id")
        seen.add(source_id)
        if src["kind"] != "synthetic_export" or src["profile_id"] != PROFILE:
            raise GateError(f"sources[{i}]: no approved mapping profile for this export")
        if src["coverage"] not in {"unknown", "declared_partial", "declared_complete"}:
            raise GateError(f"sources[{i}].coverage: invalid")
        if src["scope"] != context["scope"]:
            raise GateError(f"sources[{i}].scope: differs from analysis scope")
        utc(src["exported_at"], f"sources[{i}].exported_at")
        if snapshot_time is None:
            snapshot_time = src["exported_at"]
        elif src["exported_at"] != snapshot_time:
            raise GateError(f"sources[{i}].exported_at: cross-snapshot joins require an approved temporal rule")
        if not isinstance(src["sha256"], str) or len(src["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in src["sha256"]):
            raise GateError(f"sources[{i}].sha256: expected lowercase SHA-256")
        relative = Path(identifier(src["path"], f"sources[{i}].path"))
        if relative.is_absolute() or ".." in relative.parts:
            raise GateError(f"sources[{i}].path: must be relative to input file")
        path = (base / relative).resolve()
        if not path.is_relative_to(base.resolve()):
            raise GateError(f"sources[{i}].path: resolves outside input directory")
        try:
            source_bytes = path.read_bytes()
        except OSError as exc:
            raise GateError(f"sources[{i}]: missing or unreadable file: {exc}") from exc
        if hashlib.sha256(source_bytes).hexdigest() != src["sha256"]:
            raise GateError(f"sources[{i}]: missing file or SHA-256 mismatch")
        raw = parse_json(source_bytes, path)
        exact_keys(raw, {"schema_version", "records"}, set(), str(path))
        if raw["schema_version"] != PROFILE or not isinstance(raw["records"], list):
            raise GateError(f"{path}: unsupported illustrative export structure")
        if "record_count" in src and (type(src["record_count"]) is not int or src["record_count"] != len(raw["records"])):
            raise GateError(f"sources[{i}].record_count: does not match records")
        sources.append((src, path, raw))
    return context, sources


def normalize(context: dict[str, Any], sources: list[tuple[dict[str, Any], Path, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    facts: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    duplicate_keys: set[tuple[str, str]] = set()
    total = 0
    for src, _, raw in sources:
        for i, record in enumerate(raw["records"]):
            total += 1
            pointer = f"/records/{i}"
            ref = {"source_id": src["source_id"], "file_sha256": src["sha256"], "record_pointer": pointer}
            try:
                if not isinstance(record, dict) or record.get("record_type") not in {"node", "finding", "edge"}:
                    raise GateError("unknown record type")
                kind = record["record_type"]
                shared = {"record_type", "id", "scope", "observed_at", "support"}
                fields = {"node": {"node_type"}, "finding": {"asset_ref"}, "edge": {"from", "to", "relation", "preconditions", "postcondition"}}[kind]
                exact_keys(record, shared | fields, set(), pointer)
                identifier(record["id"], f"{pointer}.id")
                if record["scope"] != context["scope"] or record["scope"] != src["scope"]:
                    raise GateError("scope mismatch")
                observed = utc(record["observed_at"], f"{pointer}.observed_at")
                if utc_time(observed, f"{pointer}.observed_at") > utc_time(src["exported_at"], "source.exported_at"):
                    raise GateError("observation after export")
                window = context.get("time_window")
                if window and not utc_time(window["start"], "time_window.start") <= utc_time(observed, f"{pointer}.observed_at") <= utc_time(window["end"], "time_window.end"):
                    raise GateError("outside analysis time window")
                if record["support"] not in {"observed", "hypothesis"}:
                    raise GateError("support must be observed or hypothesis")
                key = (kind, record["id"])
                if key in seen:
                    if key not in duplicate_keys:
                        original = seen[key]
                        facts.remove(original)
                        quarantine.append({"source": original["source"], "reason": "duplicate record identifier"})
                        duplicate_keys.add(key)
                    raise GateError("duplicate record identifier")
                if kind == "node":
                    if record["node_type"] not in NODE_TYPES:
                        raise GateError("unsupported node type")
                    claim = {"subject": record["id"], "predicate": "is_node_type", "object": record["node_type"]}
                elif kind == "finding":
                    identifier(record["asset_ref"], f"{pointer}.asset_ref")
                    claim = {"subject": record["id"], "predicate": "finding_on_asset", "object": record["asset_ref"]}
                else:
                    for field in ("from", "to"):
                        identifier(record[field], f"{pointer}.{field}")
                    if record["relation"] not in RELATIONS or record["postcondition"] not in RELATIONS[record["relation"]]:
                        raise GateError("unsupported relation or postcondition")
                    if (not isinstance(record["preconditions"], list)
                            or (record["relation"] != "service_depends_on" and not record["preconditions"])
                            or (record["relation"] == "service_depends_on" and record["preconditions"])
                            or any(p not in CAPABILITIES for p in record["preconditions"])):
                        raise GateError("transition requires declared valid preconditions; dependency requires none")
                    claim = {"subject": record["from"], "predicate": record["relation"], "object": record["to"]}
                evidence_id = "E-" + digest({"source": ref, "record": record})[:16]
                fact = {"evidence_id": evidence_id, "class": record["support"], "claim": claim,
                        "source": ref, "observation_time": observed, "scope": src["scope"],
                        "transform_version": VERSION, "confidence": "high" if record["support"] == "observed" else "low",
                        "record": record}
                facts.append(fact)
                seen[key] = fact
            except (GateError, KeyError, TypeError) as exc:
                quarantine.append({"source": ref, "reason": str(exc)})
    counts = {"raw": total, "accepted": len(facts), "quarantined": len(quarantine), "rejected": 0}
    if counts["raw"] != counts["accepted"] + counts["quarantined"] + counts["rejected"]:
        raise GateError("G2: record counts do not reconcile")
    return facts, quarantine, counts


def build_graph(facts: list[dict[str, Any]], crowns: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = {f["record"]["id"]: f for f in facts if f["record"]["record_type"] == "node"}
    findings = [f for f in facts if f["record"]["record_type"] == "finding"]
    edges = [f for f in facts if f["record"]["record_type"] == "edge"]
    errors: list[dict[str, Any]] = []
    valid_findings = []
    for f in findings:
        asset = nodes.get(f["record"]["asset_ref"])
        if asset is None or asset["record"]["node_type"] != "asset":
            errors.append({"evidence_id": f["evidence_id"], "reason": "finding asset missing or not an asset"})
        else:
            valid_findings.append(f)
    valid_edges = []
    for edge in edges:
        row = edge["record"]
        if row["from"] not in nodes or row["to"] not in nodes:
            errors.append({"evidence_id": edge["evidence_id"], "reason": "edge endpoint missing"})
        elif row["from"] == row["to"]:
            errors.append({"evidence_id": edge["evidence_id"], "reason": "self transition invalid"})
        elif row["relation"] == "reachable_from" and (
            nodes[row["from"]]["record"]["node_type"] not in {"asset", "identity"}
            or nodes[row["to"]]["record"]["node_type"] != "asset"
        ):
            errors.append({"evidence_id": edge["evidence_id"], "reason": "reachable_from requires asset or identity source and asset target"})
        elif row["relation"] == "permission_to_act" and (
            nodes[row["from"]]["record"]["node_type"] not in {"asset", "identity"}
            or nodes[row["to"]]["record"]["node_type"] not in {"asset", "data"}
        ):
            errors.append({"evidence_id": edge["evidence_id"], "reason": "permission_to_act requires asset or identity source and asset or data target"})
        elif row["relation"] == "accesses_data" and (
            nodes[row["from"]]["record"]["node_type"] not in {"asset", "identity"}
            or nodes[row["to"]]["record"]["node_type"] != "data"
        ):
            errors.append({"evidence_id": edge["evidence_id"], "reason": "accesses_data requires asset or identity source and data target"})
        elif row["relation"] == "service_depends_on" and (
            nodes[row["from"]]["record"]["node_type"] != "service"
            or nodes[row["to"]]["record"]["node_type"] not in {"asset", "service"}
        ):
            errors.append({"evidence_id": edge["evidence_id"], "reason": "dependency requires service source and asset or service target"})
        else:
            valid_edges.append(edge)
    for crown in crowns:
        if crown["asset_ref"] not in nodes:
            errors.append({"crown_jewel": crown["asset_ref"], "reason": "crown jewel absent from declared export"})
        elif nodes[crown["asset_ref"]]["record"]["node_type"] != "asset":
            errors.append({"crown_jewel": crown["asset_ref"], "reason": "crown jewel reference is not an asset"})
    return nodes, valid_findings, valid_edges, errors


def trace_paths(nodes: dict[str, dict[str, Any]], findings: list[dict[str, Any]], edges: list[dict[str, Any]], crowns: list[dict[str, Any]], max_depth: int = 8) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    targets = {c["asset_ref"]: c for c in crowns
               if c["asset_ref"] in nodes and nodes[c["asset_ref"]]["record"]["node_type"] == "asset"}
    adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)
    dependencies: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if edge["record"]["relation"] == "service_depends_on":
            dependencies[edge["record"]["to"]].append(edge)
        else:
            adjacency[edge["record"]["from"]].append(edge)
    for rows in adjacency.values():
        rows.sort(key=lambda e: (e["record"]["id"], e["evidence_id"]))
    found: dict[str, dict[str, Any]] = {}
    partial: list[dict[str, Any]] = []
    for finding in sorted(findings, key=lambda f: f["record"]["id"]):
        start = finding["record"]["asset_ref"]
        finding_gaps = [f"{finding['record']['id']}: hypothetical starting finding"] if finding["class"] == "hypothesis" else []
        if nodes[start]["class"] == "hypothesis":
            finding_gaps.append(f"{start}: hypothetical starting asset")
        stack = [(start, [start], [], {"finding_on_asset"}, finding_gaps,
                  [finding["evidence_id"], nodes[start]["evidence_id"]])]
        while stack:
            current, visited, steps, capabilities, gaps, evidence = stack.pop()
            if current in targets:
                signature = {"finding": finding["record"]["id"], "target": current,
                             "sequence": [(s["from"], s["relation"], s["to"], tuple(sorted(set(s["preconditions"]))),
                                           s["postcondition"], s["support"], tuple(s["missing_preconditions"])) for s in steps],
                             "scope": finding["scope"]}
                path_id = "P-" + digest(signature)[:16]
                prior = found.get(path_id)
                if prior is None:
                    supported_nodes = [start] if not finding_gaps and nodes[start]["class"] == "observed" else []
                    supported_steps = []
                    for step in steps:
                        if (not supported_nodes or step["support"] != "observed"
                                or step["missing_preconditions"] or nodes[step["to"]]["class"] != "observed"):
                            break
                        supported_nodes.append(step["to"])
                        supported_steps.append(step)
                    asset_ids = sorted({n for n in supported_nodes if nodes[n]["record"]["node_type"] == "asset"})
                    linked_services = [e for asset in asset_ids for e in dependencies.get(asset, [])
                                       if e["class"] == "observed" and nodes[e["record"]["from"]]["class"] == "observed"]
                    service_ids = sorted({e["record"]["from"] for e in linked_services})
                    service_refs = sorted({ref for e in linked_services
                                           for ref in (e["evidence_id"], nodes[e["record"]["from"]]["evidence_id"])})
                    cia = sorted({{"read": "confidentiality", "modify": "integrity", "disrupt": "availability"}[s["postcondition"]]
                                 for s in supported_steps if not finding_gaps and s["postcondition"] in {"read", "modify", "disrupt"}})
                    labels = [finding["confidence"]] + [nodes[n]["confidence"] for n in visited] + [s["confidence"] for s in steps]
                    confidence = min(labels, key=lambda label: CONFIDENCE_ORDER[label])
                    if gaps:
                        confidence = "low"
                    elif CONFIDENCE_ORDER[confidence] > CONFIDENCE_ORDER["medium"]:
                        confidence = "medium"  # A path is a rule-derived relationship, never a direct source fact.
                    supported_step_count = len(supported_steps) if not finding_gaps else 0
                    found[path_id] = {"path_id": path_id, "start_finding": finding["record"]["id"],
                                      "start_asset": start, "target": current, "path_class": "candidate" if gaps else "supported_structural",
                                      "premise": "conditional_successful_exploitation_of_finding", "steps": steps,
                                      "evidence_refs": sorted(set(evidence + service_refs)), "gaps": sorted(set(gaps)),
                                      "confidence": confidence, "confidence_scope": "evidence_support",
                                      "blast_radius": {"evidenced_asset_ids": asset_ids, "evidenced_asset_count": len(asset_ids),
                                                       "evidenced_service_ids": service_ids, "evidenced_service_count": len(service_ids),
                                                       "service_dependency_evidence_refs": service_refs,
                                                       "coverage": "bounded_to_supported_path"},
                                      "impact": {"potential_cia": cia, "business_rating": "unrated",
                                                 "reason": "No approved impact profile or business criteria supplied"},
                                      "rank_inputs": {"crown_priority": targets[current]["priority"],
                                                      "business_rating": "unrated", "supported_step_count": supported_step_count,
                                                      "total_step_count": len(steps)},
                                      "deduplication_key": digest(signature), "scope": finding["scope"]}
                else:
                    prior["evidence_refs"] = sorted(set(prior["evidence_refs"] + evidence))
                    for existing_step, new_step in zip(prior["steps"], steps):
                        existing_step["supporting_evidence_refs"] = sorted(set(
                            existing_step["supporting_evidence_refs"] + new_step["supporting_evidence_refs"]))
                continue
            if len(steps) >= max_depth:
                partial.append({"start_finding": finding["record"]["id"], "stopped_at": current, "reason": "depth limit"})
                continue
            advanced = False
            for edge in reversed(adjacency.get(current, [])):
                row = edge["record"]
                if row["to"] in visited:
                    continue
                advanced = True
                missing = sorted(set(row["preconditions"]) - capabilities)
                next_gaps = gaps + ([f"{row['id']}: missing capability {', '.join(missing)}"] if missing else [])
                if row["support"] == "hypothesis":
                    next_gaps.append(f"{row['id']}: hypothetical relationship")
                if nodes[row["to"]]["class"] == "hypothesis":
                    next_gaps.append(f"{row['to']}: hypothetical node")
                step = {"edge_id": row["id"], "from": current, "to": row["to"], "relation": row["relation"],
                        "preconditions": row["preconditions"], "missing_preconditions": missing,
                        "postcondition": row["postcondition"], "support": row["support"],
                        "evidence_ref": edge["evidence_id"], "supporting_evidence_refs": [edge["evidence_id"]],
                        "confidence": edge["confidence"]}
                stack.append((row["to"], visited + [row["to"]], steps + [step],
                              capabilities | {row["postcondition"]}, next_gaps,
                              evidence + [edge["evidence_id"], nodes[row["to"]]["evidence_id"]]))
            if not advanced:
                partial.append({"start_finding": finding["record"]["id"], "stopped_at": current, "reason": "no further valid transition"})
    paths = list(found.values())
    return paths, sorted(partial, key=lambda x: (x["start_finding"], x["stopped_at"], x["reason"]))


def rank_paths(paths: list[dict[str, Any]], crowns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priorities = {c["asset_ref"]: c["priority"] for c in crowns}
    def key(path: dict[str, Any]) -> tuple[Any, ...]:
        priority = priorities[path["target"]]
        total_steps = path["rank_inputs"]["total_step_count"]
        completeness = Fraction(path["rank_inputs"]["supported_step_count"], total_steps) if total_steps else Fraction(1, 1)
        return (0 if path["path_class"] == "supported_structural" else 1,
                priority is None, priority if priority is not None else 0,
                -path["blast_radius"]["evidenced_asset_count"],
                -path["blast_radius"]["evidenced_service_count"],
                -completeness, path["path_id"])
    return sorted(paths, key=key)


def query_intent(start: str, target: str, scope: str) -> dict[str, Any]:
    return {"schema_version": "attackpath.query_intent/v1", "start_selector": identifier(start, "start"),
            "target_selector": identifier(target, "target"), "relationships": ["[DOCUMENTED_WIZ_RELATIONSHIP_TYPES]"],
            "scope_filters": [identifier(scope, "scope")], "projected_fields": ["[DOCUMENTED_WIZ_FIELDS]"],
            "documentation_profile_id": "[PENDING_WIZ_DOCS]", "operation_profile_id": "[PENDING_WIZ_DOCS]",
            "api_operation": "[PENDING_WIZ_DOCS]", "pagination": "[PENDING_WIZ_DOCS]",
            "authentication": "[PENDING_WIZ_DOCS]", "render_status": "blocked_pending_docs"}


def make_actions(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Produce rule-bound options tied to a first transition or direct finding."""
    actions = []
    for path in paths:
        target_type = "transition" if path["steps"] else "finding"
        target = path["steps"][0]["edge_id"] if path["steps"] else path["start_finding"]
        target_label = f"transition {target}" if path["steps"] else f"finding {target} on the crown jewel"
        actions.append({"action_id": "A-" + path["path_id"][2:], "path_id": path["path_id"],
                        "target_type": target_type, "target_id": target, "class": "recommendation",
                        "proposal": f"Review {target_label}; reduce the cited exposure at a feasible control point.",
                        "validation": f"Check whether {target_label} changed in a later same-scope export; use an authorized test to validate the control.",
                        "monitoring": f"Review available telemetry for activity relevant to {target_label}.",
                        "investigation": f"Confirm the exploit premise, prerequisites for {target_label}, and source coverage with the asset owner.",
                        "evidence_refs": path["evidence_refs"], "owner": None, "status": "proposed", "closure_evidence": None})
    return actions


def collect_reviews(report: dict[str, Any], reviews: list[dict[str, Any]]) -> dict[str, Any]:
    """Attach advisory opinions without changing source facts or gate decisions."""
    if not isinstance(reviews, list):
        raise GateError("reviews: expected list")
    evidence_ids = {fact["evidence_id"] for fact in report["evidence"]}
    allowed_specialists = {"path_skeptic", "impact_reviewer", "attack_reviewer", "action_planner", "claim_auditor"}
    allowed_verdicts = {"supported", "candidate", "invalid", "unrated", "mapped", "abstain", "proposed", "unsupported"}
    checked = []
    for i, value in enumerate(reviews):
        where = f"reviews[{i}]"
        review = exact_keys(value, {"schema_version", "specialist", "prompt_version", "input_sha256",
                                    "model_settings", "verdict", "rationale", "evidence_refs", "alternatives",
                                    "validation_questions", "disagrees_with_gate", "human_disposition"}, set(), where)
        if review["schema_version"] != "attackpath.review/v1":
            raise GateError(f"{where}.schema_version: unsupported")
        if review["specialist"] not in allowed_specialists or review["verdict"] not in allowed_verdicts:
            raise GateError(f"{where}: invalid specialist or verdict")
        identifier(review["prompt_version"], f"{where}.prompt_version")
        sha = review["input_sha256"]
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise GateError(f"{where}.input_sha256: expected lowercase SHA-256")
        if review["model_settings"] is not None and not isinstance(review["model_settings"], dict):
            raise GateError(f"{where}.model_settings: expected object or null")
        identifier(review["rationale"], f"{where}.rationale")
        for field in ("evidence_refs", "alternatives", "validation_questions"):
            if not isinstance(review[field], list) or any(not isinstance(item, str) for item in review[field]):
                raise GateError(f"{where}.{field}: expected list of strings")
        if not set(review["evidence_refs"]) <= evidence_ids:
            raise GateError(f"{where}.evidence_refs: unknown evidence")
        if not isinstance(review["disagrees_with_gate"], bool):
            raise GateError(f"{where}.disagrees_with_gate: expected boolean")
        if review["human_disposition"] is not None:
            identifier(review["human_disposition"], f"{where}.human_disposition")
        checked.append(copy.deepcopy(review))
    ordered = sorted(checked, key=lambda row: canonical(row))
    if len({canonical(row) for row in ordered}) != len(ordered):
        raise GateError("reviews: duplicate opinion")
    result = copy.deepcopy(report)
    result["human_review"] = ordered
    return result


def audit_report(report: dict[str, Any], sources: list[tuple[dict[str, Any], Path, Any]]) -> None:
    """Rebuild report claims from the immutable, hash-checked source snapshots."""
    context = report["context"]
    source_by_id = {source["source_id"]: (source, raw) for source, _, raw in sources}
    for fact in report["evidence"]:
        ref = fact["source"]
        pair = source_by_id.get(ref["source_id"])
        if pair is None or pair[0]["sha256"] != ref["file_sha256"]:
            raise GateError("G7: evidence source hash does not match manifest")
        pointer = ref["record_pointer"]
        if not pointer.startswith("/records/") or not pointer[9:].isdigit():
            raise GateError("G7: evidence record pointer invalid")
        index = int(pointer[9:])
        records = pair[1]["records"]
        if index >= len(records) or fact["record"] != records[index]:
            raise GateError("G7: evidence record differs from cited source pointer")
    facts, quarantine, counts = normalize(context, sources)
    if (report["evidence"] != sorted(facts, key=lambda f: f["evidence_id"])
            or report["quarantine"] != quarantine or report["reconciliation"] != counts):
        raise GateError("G7: evidence claims or reconciliation differ from sources")
    nodes, findings, edges, graph_errors = build_graph(facts, context["crown_jewels"])
    if report["graph_exclusions"] != graph_errors:
        raise GateError("G7: graph exclusions differ from cited evidence")
    expected_graph = {"schema_version": "attackpath.graph/v1",
                      "nodes": [{"node_id": key, "node_type": value["record"]["node_type"],
                                 "evidence_ref": value["evidence_id"], "support": value["class"], "scope": value["scope"],
                                 "observed_at": value["observation_time"]} for key, value in sorted(nodes.items())],
                      "findings": [{"finding_id": f["record"]["id"], "asset_ref": f["record"]["asset_ref"],
                                    "evidence_ref": f["evidence_id"]} for f in sorted(findings, key=lambda f: f["record"]["id"])],
                      "edges": [{"edge_id": e["record"]["id"], "from": e["record"]["from"], "to": e["record"]["to"],
                                 "relation": e["record"]["relation"], "preconditions": e["record"]["preconditions"],
                                 "postcondition": e["record"]["postcondition"], "support": e["class"],
                                 "evidence_ref": e["evidence_id"], "scope": e["scope"],
                                 "observed_at": e["observation_time"]} for e in sorted(edges, key=lambda e: e["record"]["id"])]}
    if report["graph"] != expected_graph:
        raise GateError("G7: graph relationship differs from cited evidence")
    expected_paths, expected_partial = trace_paths(nodes, findings, edges, context["crown_jewels"])
    expected_paths = rank_paths(expected_paths, context["crown_jewels"])
    if (report["supported_paths"] != [p for p in expected_paths if p["path_class"] == "supported_structural"]
            or report["candidate_paths"] != [p for p in expected_paths if p["path_class"] == "candidate"]
            or report["partial_paths"] != expected_partial):
        raise GateError("G7: path, impact, confidence, or ranking differs from cited evidence")
    if report["actions"] != make_actions(expected_paths):
        raise GateError("G7: proposed action differs from rule-bound, cited path")
    if collect_reviews(report, report["human_review"])["human_review"] != report["human_review"]:
        raise GateError("G7: specialist reviews are not in canonical order")


def analyze(input_path: Path) -> dict[str, Any]:
    try:
        input_bytes = input_path.read_bytes()
    except OSError as exc:
        raise GateError(f"{input_path}: cannot read JSON: {exc}") from exc
    raw_input = parse_json(input_bytes, input_path)
    input_sha = hashlib.sha256(input_bytes).hexdigest()
    context, sources = validate_input(raw_input, input_path.parent)
    facts, quarantine, counts = normalize(context, sources)
    nodes, findings, edges, graph_errors = build_graph(facts, context["crown_jewels"])
    paths, partial = trace_paths(nodes, findings, edges, context["crown_jewels"])
    paths = rank_paths(paths, context["crown_jewels"])
    evidence_ids = {f["evidence_id"] for f in facts}
    for path in paths:
        if not path["evidence_refs"] or not set(path["evidence_refs"]) <= evidence_ids:
            raise GateError("G7: path lacks source-backed evidence refs")
        if any(step["evidence_ref"] not in step["supporting_evidence_refs"] or
               not set(step["supporting_evidence_refs"]) <= set(path["evidence_refs"]) for step in path["steps"]):
            raise GateError("G7: path step lacks cited evidence")
    actions = make_actions(paths)
    profile_path = Path(__file__).resolve().parents[1] / "profiles" / "illustrative_canonical-v1.json"
    run = {"tool_version": VERSION, "rule_version": "attackpath.rules/v1",
           "rule_sha256": file_hash(Path(__file__).resolve()),
           "profile_sha256": {PROFILE: file_hash(profile_path)},
           "input_sha256": input_sha,
           "source_sha256": {src["source_id"]: src["sha256"] for src, _, _ in sources},
           "profile_versions": [PROFILE], "reference_versions": [], "prompt_versions": [],
           "run_id": "RUN-" + digest({"input": raw_input, "sources": [s["sha256"] for s, _, _ in sources], "version": VERSION})[:16]}
    coverage = [{"source_id": src["source_id"], "declared_coverage": src["coverage"],
                 "independently_verified_complete": False} for src, _, _ in sources]
    graph = {"schema_version": "attackpath.graph/v1",
             "nodes": [{"node_id": key, "node_type": value["record"]["node_type"],
                        "evidence_ref": value["evidence_id"], "support": value["class"], "scope": value["scope"],
                        "observed_at": value["observation_time"]} for key, value in sorted(nodes.items())],
             "findings": [{"finding_id": f["record"]["id"], "asset_ref": f["record"]["asset_ref"],
                           "evidence_ref": f["evidence_id"]} for f in sorted(findings, key=lambda f: f["record"]["id"])],
             "edges": [{"edge_id": e["record"]["id"], "from": e["record"]["from"], "to": e["record"]["to"],
                        "relation": e["record"]["relation"], "preconditions": e["record"]["preconditions"],
                        "postcondition": e["record"]["postcondition"], "support": e["class"],
                        "evidence_ref": e["evidence_id"], "scope": e["scope"],
                        "observed_at": e["observation_time"]} for e in sorted(edges, key=lambda e: e["record"]["id"])]}
    report = {"schema_version": "attackpath.report/v1", "run": run, "context": context,
              "coverage": coverage, "reconciliation": counts, "evidence": sorted(facts, key=lambda f: f["evidence_id"]), "graph": graph,
              "quarantine": quarantine, "graph_exclusions": graph_errors,
              "supported_paths": [p for p in paths if p["path_class"] == "supported_structural"],
              "candidate_paths": [p for p in paths if p["path_class"] == "candidate"],
              "partial_paths": partial, "technique_mappings": [], "attack_flow": {"status": "pending_reference_bundle"},
              "actions": actions, "assumptions": ["Paths are conditional on successful exploitation of the starting finding."],
              "evidence_gaps": sorted({gap for p in paths for gap in p["gaps"]}),
              "alternative_interpretations": [], "human_review": [],
              "gate_results": {"G1": "pass", "G2": "pass" if not quarantine else "warning_quarantined",
                               "G3": "pass" if not graph_errors else "warning_excluded",
                               "G4": "pass", "G5": "unrated_pending_profile", "G6": "pending_reference_bundle",
                               "G7": "pass", "G8": "pass"}}
    # G8 checks internal references and canonical serialization in a second pass.
    if any(action["path_id"] not in {p["path_id"] for p in paths} for action in actions):
        raise GateError("G8: action refers to absent path")
    if any(ref not in evidence_ids for action in actions for ref in action["evidence_refs"]):
        raise GateError("G7: action lacks cited evidence")
    if any(ref not in evidence_ids for kind in ("nodes", "findings", "edges") for item in graph[kind] for ref in [item["evidence_ref"]]):
        raise GateError("G8: graph item lacks cited evidence")
    audit_report(report, sources)
    for src, path, _ in sources:
        try:
            current_hash = file_hash(path)
        except OSError as exc:
            raise GateError("G1: source disappeared during analysis") from exc
        if current_hash != src["sha256"]:
            raise GateError("G1: source changed during analysis")
    try:
        current_input_hash = file_hash(input_path)
    except OSError as exc:
        raise GateError("G1: input disappeared during analysis") from exc
    if current_input_hash != input_sha:
        raise GateError("G1: input changed during analysis")
    if json.loads(canonical(report)) != report:
        raise GateError("G8: canonical round trip failed")
    return report
