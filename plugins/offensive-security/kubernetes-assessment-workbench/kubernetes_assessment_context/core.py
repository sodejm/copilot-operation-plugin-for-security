"""Reconcile explicit approval with a sanitized, local Kubernetes observation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_BYTES = 131_072
MAX_ITEMS = 256
SURFACES = frozenset({"api_server", "namespaced_resources", "control_plane", "nodes", "network"})
ACCESS = frozenset({"accessible", "denied", "unknown"})
SURFACE_ACCESS = ACCESS | {"unavailable"}
FACT_ACCESS = SURFACE_ACCESS | {"managed_unavailable"}
FACT_FIELDS = (
    "server_version",
    "distribution",
    "container_runtime",
    "node_os",
    "network_model",
    "admission_controls",
    "control_plane_access",
    "node_access",
)
SENSITIVE_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "secret_key",
        "client_key",
        "client_key_data",
        "private_key",
        "certificate",
        "client_certificate",
        "client_certificate_data",
        "certificate_authority_data",
        "kubeconfig",
        "server",
        "server_url",
        "api_key",
        "auth_provider",
        "exec",
    }
)


class GateError(ValueError):
    """Stable input or scope gate failure; never contains submitted values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise GateError("duplicate_json_key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise GateError("invalid_json")


def load_record(path: str | Path) -> dict[str, Any]:
    """Load one bounded JSON file; never consult kubeconfig or the network."""
    target = Path(path)
    try:
        with target.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise GateError("input_too_large")
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    except GateError:
        raise
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as error:
        raise GateError("invalid_json") from error
    if not isinstance(record, dict):
        raise GateError("invalid_record")
    return record


def _scan(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise GateError("input_too_deep")
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise GateError("input_too_large")
        for key, child in value.items():
            if not isinstance(key, str):
                raise GateError("invalid_record")
            if key.lower().replace("-", "_") in SENSITIVE_KEYS:
                raise GateError("credential_field")
            _scan(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise GateError("input_too_large")
        for child in value:
            _scan(child, depth + 1)
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise GateError("invalid_record")


def _mapping(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError(code)
    return value


def _label(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or value != value.strip():
        raise GateError(code)
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise GateError(code)
    return value


def _context(value: Any) -> dict[str, str]:
    record = _mapping(value, "invalid_context")
    if set(record) != {"name", "cluster", "user"}:
        raise GateError("invalid_context")
    return {key: _label(record[key], "invalid_context") for key in ("name", "cluster", "user")}


def _approved_list(value: Any, code: str, *, namespace: bool = False) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS:
        raise GateError(code)
    labels = [_label(item, code) for item in value]
    if len(set(labels)) != len(labels):
        raise GateError(code)
    if namespace and any(item.lower() in {"all", "*", "all-namespaces"} or "*" in item for item in labels):
        raise GateError("wildcard_namespace")
    return labels


def _anchor(value: Any) -> dict[str, str]:
    anchor = _mapping(value, "invalid_identity_anchor")
    if set(anchor) != {"namespace", "uid"}:
        raise GateError("invalid_identity_anchor")
    return {key: _label(anchor[key], "invalid_identity_anchor") for key in ("namespace", "uid")}


def _access_rows(value: Any, name: str, key: str, statuses: frozenset[str]) -> dict[str, str]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise GateError(name)
    rows: dict[str, str] = {}
    for raw in value:
        row = _mapping(raw, name)
        if set(row) != {key, "status"}:
            raise GateError(name)
        label = _label(row[key], name)
        if not isinstance(row["status"], str) or row["status"] not in statuses or label in rows:
            raise GateError(name)
        rows[label] = row["status"]
    return rows


def _facts(value: Any) -> dict[str, Any]:
    raw = _mapping(value, "invalid_cluster_facts")
    if set(raw) - set(FACT_FIELDS):
        raise GateError("invalid_cluster_facts")
    result: dict[str, Any] = {}
    for field in FACT_FIELDS:
        item = raw.get(field, "unknown")
        if field == "admission_controls":
            if item == "unknown":
                result[field] = "unknown"
            elif isinstance(item, list) and len(item) <= MAX_ITEMS:
                result[field] = sorted(set(_label(entry, "invalid_cluster_facts") for entry in item))
            else:
                raise GateError("invalid_cluster_facts")
        elif field in {"control_plane_access", "node_access"}:
            if not isinstance(item, str) or item not in FACT_ACCESS:
                raise GateError("invalid_cluster_facts")
            result[field] = item
        else:
            result[field] = _label(item, "invalid_cluster_facts")
    return result


def assess(record: dict[str, Any]) -> dict[str, Any]:
    """Produce an offline scope and identity report, never an execution permit."""
    _mapping(record, "invalid_record")
    _scan(record)
    if set(record) != {"schema_version", "mode", "plan", "observation"} or record["schema_version"] != "1.0":
        raise GateError("invalid_record")
    if record["mode"] != "offline":
        raise GateError("unsupported_mode")
    plan = _mapping(record["plan"], "invalid_plan")
    observation = _mapping(record["observation"], "invalid_observation")
    if set(plan) - {"approval_reference", "context", "namespaces", "surfaces", "identity_anchor"}:
        raise GateError("invalid_plan")
    if set(observation) - {
        "current_context",
        "contexts",
        "identity_anchor",
        "namespace_access",
        "surface_access",
        "cluster_facts",
    }:
        raise GateError("invalid_observation")
    approval = _label(plan.get("approval_reference"), "missing_approval_reference")
    selected = _context(plan.get("context"))
    namespaces = _approved_list(plan.get("namespaces"), "invalid_namespaces", namespace=True)
    surfaces = _approved_list(plan.get("surfaces"), "invalid_surfaces")
    if set(surfaces) - SURFACES:
        raise GateError("unknown_surface")
    observed = _context(observation.get("current_context"))
    inventory = observation.get("contexts")
    if not isinstance(inventory, list) or not inventory or len(inventory) > MAX_ITEMS:
        raise GateError("invalid_context_inventory")
    contexts = [_context(item) for item in inventory]
    names = [item["name"] for item in contexts]
    if len(set(names)) != len(names):
        raise GateError("duplicate_context_name")
    if observed != selected or contexts.count(selected) != 1:
        raise GateError("context_mismatch")

    approved_anchor = _anchor(plan["identity_anchor"]) if "identity_anchor" in plan else None
    observed_anchor = _anchor(observation["identity_anchor"]) if "identity_anchor" in observation else None
    if approved_anchor and observed_anchor and approved_anchor != observed_anchor:
        raise GateError("identity_anchor_mismatch")
    identity_status = "matched_sanitized_export" if approved_anchor and observed_anchor else "unresolved"
    namespace_access = _access_rows(
        observation.get("namespace_access", []), "invalid_namespace_access", "namespace", ACCESS
    )
    surface_access = _access_rows(
        observation.get("surface_access", []), "invalid_surface_access", "surface", SURFACE_ACCESS
    )
    facts = _facts(observation.get("cluster_facts", {}))
    namespace_rows = [
        {"namespace": item, "status": namespace_access.get(item, "unknown")} for item in sorted(namespaces)
    ]
    surface_rows = [{"surface": item, "status": surface_access.get(item, "unknown")} for item in sorted(surfaces)]
    blockers = []
    if identity_status == "unresolved":
        blockers.append("stable_identity_unresolved")
    if any(row["status"] != "accessible" for row in namespace_rows):
        blockers.append("namespace_access_incomplete")
    if any(row["status"] != "accessible" for row in surface_rows):
        blockers.append("surface_access_incomplete")
    limitations = []
    if facts["control_plane_access"] != "accessible":
        limitations.append("control_plane_unavailable")
    if facts["node_access"] != "accessible":
        limitations.append("node_access_unavailable")
    return {
        "schema_version": "1.0",
        "evidence_origin": "sanitized_offline_export",
        "approval_reference": approval,
        "selected_context": selected,
        "cluster_identity": {
            "method": "namespace_uid_anchor" if identity_status != "unresolved" else "unresolved",
            "status": identity_status,
            "anchor": approved_anchor if identity_status != "unresolved" else None,
        },
        "namespaces": namespace_rows,
        "surfaces": surface_rows,
        "cluster_facts": facts,
        "blockers": blockers,
        "limitations": limitations,
        "live_execution_ready": False,
        "network_requests": 0,
    }
