"""Exact component binding for the bounded synthetic CVE workflow.

These records are evidence assertions, not an advisory service or a proof of
non-exploitability. Unknown versions and digests remain unresolved.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

FIELDS = ("name", "ecosystem", "version", "source_sha256")


def _records(value: Any, key: str) -> list[dict[str, Any]]:
    records = value.get(key, []) if isinstance(value, dict) else []
    return [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []


def _identity(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, dict) or any(not isinstance(value.get(key), str) or not value[key] for key in FIELDS):
        return None
    if not re.fullmatch(r"[a-f0-9]{64}", value["source_sha256"]):
        return None
    return tuple(value[key] for key in FIELDS)


def match_dependency(advisory: dict, inventory: dict) -> dict:
    known = []
    valid_advisory = (
        advisory.get("schema_version") == "cops.synthetic-advisory/v1"
        and isinstance(advisory.get("id"), str)
        and bool(advisory["id"])
    )
    for entry in _records(advisory, "components"):
        component = {**entry, "name": advisory.get("package"), "ecosystem": advisory.get("ecosystem")}
        if _identity(component) and type(component.get("affected")) is bool:
            known.append(component)
    packages = _records(inventory, "packages")
    candidates = [
        item
        for item in packages
        if item.get("name") == advisory.get("package") and item.get("ecosystem") == advisory.get("ecosystem")
    ]
    matches = []
    for package in candidates:
        identities = [item for item in known if _identity(item) == _identity(package) and _identity(package)]
        if len(identities) == 1:
            matches.append(identities[0])
    valid_components = isinstance(advisory.get("components"), list) and len(known) == len(advisory["components"])
    valid_inventory = (
        isinstance(inventory.get("packages"), list)
        and len(packages) == len(inventory["packages"])
        and all(_identity(item) is not None for item in packages)
    )
    resolved = (
        valid_advisory
        and valid_components
        and valid_inventory
        and inventory.get("complete") is True
        and bool(candidates)
        and len(matches) == len(candidates)
    )
    return {
        "advisory": advisory,
        "matches": matches,
        "resolved": resolved,
        "limitation": "exact pinned components only; no version-range or production advisory coverage",
    }


def _provenance(record: dict) -> bool:
    if not all(
        isinstance(record.get(key), str) and record[key] for key in ("execution_id", "observed_at", "evidence_ref")
    ):
        return False
    try:
        return datetime.fromisoformat(record["observed_at"].replace("Z", "+00:00")).utcoffset() is not None
    except ValueError:
        return False


def assess_reachability(match: dict, callgraph: dict, runtime: dict) -> dict:
    identities = {_identity(item): item for item in match["matches"]} if match["resolved"] else {}
    runtime_records = [
        item
        for item in _records(runtime, "modules")
        if _identity(item.get("component")) in identities
        and _provenance(item)
        and type(item.get("calls")) is int
        and item["calls"] > 0
    ]
    paths = [
        item
        for item in _records(callgraph, "paths")
        if _identity(item.get("component")) in identities and _provenance(item) and type(item.get("reachable")) is bool
    ]
    evidence = runtime_records + paths
    affected = [item for item in evidence if identities[_identity(item["component"])]["affected"]]
    reachable = any(item.get("calls", 0) > 0 or item.get("reachable") is True for item in affected)
    if not evidence:
        status = "not_established"
    elif reachable:
        status = "reachable"
    elif not any(item["affected"] for item in identities.values()):
        status = "corrected_dependency"
    else:
        status = "not_observed"
    return {
        "status": status,
        "evidence_present": bool(evidence),
        "non_exploitability_established": False,
        "dependency_match": match,
        "bound_evidence_refs": sorted({item["evidence_ref"] for item in evidence}),
    }


def assess_controls(controls: dict, assessment: dict) -> dict:
    match = assessment["dependency_match"]
    identities = {_identity(item) for item in match["matches"]} if match["resolved"] else set()
    verified = [
        item
        for item in _records(controls, "controls")
        if item.get("verified") is True
        and item.get("advisory_id") == match["advisory"].get("id")
        and _identity(item.get("component")) in identities
        and _provenance(item)
    ]
    return {"verified_controls": verified, "count": len(verified)}
