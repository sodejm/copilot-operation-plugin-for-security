"""Classify bounded offline and native-bridge Windows exports."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .core import (
    CLASSIFICATIONS,
    MAX_EVIDENCE_IDS,
    MAX_OBSERVATIONS,
    ContractError,
    _canary,
    _enum,
    _evidence_ids,
    _exact_keys,
    _token,
)

SURFACES = (
    "service_permissions",
    "scheduled_task_permissions",
    "token_privileges",
    "registry_controls",
    "filesystem_controls",
    "local_credential_references",
    "versioned_escalation_families",
)
PROTECTIONS = ("uac", "wdac", "credential_guard", "vbs", "applocker")
ARCHITECTURES = {"x86", "x64", "arm64"}
INTEGRITY = ("low", "medium", "high", "system")
BUILD_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")


def _build(value: Any, where: str, *, unknown: bool = False) -> str:
    if unknown and value == "unknown":
        return value
    if not isinstance(value, str) or len(value) > 63 or not BUILD_PATTERN.fullmatch(value):
        raise ContractError(f"{where} must be a bounded numeric build")
    return value


def _build_key(value: str) -> tuple[int, int, int, int]:
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


def _privileges(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE_IDS:
        raise ContractError(f"{where} must be a bounded list")
    result = [_token(item, where) for item in value]
    if len(result) != len(set(result)):
        raise ContractError(f"{where} has duplicate IDs")
    return result


def _boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        raise ContractError(f"{where} must be Boolean")
    return value


def _host(value: Any) -> dict[str, Any]:
    host = _exact_keys(value, {"os_build", "architecture", "token", "protections"}, "host")
    token = _exact_keys(host["token"], {"integrity", "elevated", "privileges", "privileges_complete"}, "host.token")
    elevation = token["elevated"]
    if elevation != "unknown":
        elevation = _boolean(elevation, "host.token.elevated")
    protections = _exact_keys(host["protections"], set(PROTECTIONS), "host.protections")
    return {
        "os_build": _build(host["os_build"], "host.os_build", unknown=True),
        "architecture": _enum(host["architecture"], ARCHITECTURES | {"unknown"}, "host.architecture"),
        "token": {
            "integrity": _enum(token["integrity"], set(INTEGRITY) | {"unknown"}, "host.token.integrity"),
            "elevated": elevation,
            "privileges": _privileges(token["privileges"], "host.token.privileges"),
            "privileges_complete": _boolean(token["privileges_complete"], "host.token.privileges_complete"),
        },
        "protections": {
            name: _enum(protections[name], {"enabled", "disabled", "unknown"}, f"host.protections.{name}")
            for name in PROTECTIONS
        },
    }


def _requirements(value: Any) -> dict[str, Any]:
    req = _exact_keys(value, {"build_min", "build_max", "architecture", "token", "protections"}, "requirements")
    minimum = _build(req["build_min"], "requirements.build_min")
    maximum = _build(req["build_max"], "requirements.build_max")
    if _build_key(minimum) > _build_key(maximum):
        raise ContractError("requirements build range is reversed")
    token = _exact_keys(req["token"], {"min_integrity", "elevated", "privileges"}, "requirements.token")
    protections = req["protections"]
    if not isinstance(protections, dict) or set(protections) - set(PROTECTIONS):
        raise ContractError("requirements.protections has unsupported fields")
    return {
        "build_min": minimum,
        "build_max": maximum,
        "architecture": _enum(req["architecture"], ARCHITECTURES, "requirements.architecture"),
        "token": {
            "min_integrity": _enum(token["min_integrity"], set(INTEGRITY), "requirements.token.min_integrity"),
            "elevated": _boolean(token["elevated"], "requirements.token.elevated"),
            "privileges": _privileges(token["privileges"], "requirements.token.privileges"),
        },
        "protections": {
            name: _enum(state, {"enabled", "disabled"}, f"requirements.protections.{name}")
            for name, state in sorted(protections.items())
        },
    }


def _decision(host: dict[str, Any], req: dict[str, Any]) -> str:
    unknown = False
    build = host["os_build"]
    if build == "unknown":
        unknown = True
    elif not _build_key(req["build_min"]) <= _build_key(build) <= _build_key(req["build_max"]):
        return "inapplicable"
    architecture = host["architecture"]
    if architecture == "unknown":
        unknown = True
    elif architecture != req["architecture"]:
        return "inapplicable"
    token = host["token"]
    integrity = token["integrity"]
    if integrity == "unknown":
        unknown = True
    elif INTEGRITY.index(integrity) < INTEGRITY.index(req["token"]["min_integrity"]):
        return "inapplicable"
    if token["elevated"] == "unknown":
        unknown = True
    elif token["elevated"] != req["token"]["elevated"]:
        return "inapplicable"
    if set(req["token"]["privileges"]) - set(token["privileges"]):
        if token["privileges_complete"]:
            return "inapplicable"
        unknown = True
    for name, expected in req["protections"].items():
        actual = host["protections"][name]
        if actual == "unknown":
            unknown = True
        elif actual != expected:
            return "inapplicable"
    return "unresolved" if unknown else "selected"


def assess_windows_document(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a Windows export and classify its source-reported evidence."""
    document = _exact_keys(
        payload,
        {"schema_version", "source_kind", "source_id", "bridge", "host", "coverage", "observations"},
        "document",
    )
    if document["schema_version"] != "windows-1.0":
        raise ContractError("unsupported schema version")
    source_kind = _enum(document["source_kind"], {"synthetic_lab", "operator_export"}, "source_kind")
    source_id = _token(document["source_id"], "source_id")
    bridge = _exact_keys(document["bridge"], {"mode", "platform", "capabilities", "canary_assertions"}, "bridge")
    bridge_mode = _enum(
        bridge["mode"], {"offline_windows_export", "native_windows_bridge"}, "bridge.mode"
    )
    _enum(bridge["platform"], {"windows"}, "bridge.platform")
    raw_capabilities = bridge["capabilities"]
    if not isinstance(raw_capabilities, list) or len(raw_capabilities) > len(SURFACES):
        raise ContractError("bridge.capabilities must be a bounded list")
    capabilities = [_enum(item, set(SURFACES), "bridge.capabilities") for item in raw_capabilities]
    if len(capabilities) != len(set(capabilities)):
        raise ContractError("bridge.capabilities has duplicate surfaces")
    canary_assertions = _boolean(bridge["canary_assertions"], "bridge.canary_assertions")
    if bridge_mode == "native_windows_bridge":
        if source_kind != "operator_export":
            raise ContractError("native Windows bridge requires an operator export")
        if canary_assertions:
            raise ContractError("native Windows bridge cannot assert privilege crossings")
    host = _host(document["host"])
    raw_coverage = _exact_keys(document["coverage"], set(SURFACES), "coverage")
    coverage = {
        surface: _enum(
            raw_coverage[surface], {"assessed", "not_assessed", "unsupported", "access_denied"}, f"coverage.{surface}"
        )
        for surface in SURFACES
    }
    if any(state == "assessed" and surface not in capabilities for surface, state in coverage.items()):
        raise ContractError("assessed coverage lacks declared bridge capability")
    observations = document["observations"]
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise ContractError("observations must be a bounded list")
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for raw in observations:
        item = _exact_keys(
            raw,
            {"id", "surface", "configuration", "evidence_ids", "requirements"},
            "observation",
            {"canary", "family_id"},
        )
        obs_id = _token(item["id"], "observation.id")
        if obs_id in seen:
            raise ContractError("duplicate observation ID")
        seen.add(obs_id)
        surface = _enum(item["surface"], set(SURFACES), "observation.surface")
        if coverage[surface] != "assessed":
            raise ContractError("observation is present on a surface without assessed coverage")
        if (surface == "versioned_escalation_families") != ("family_id" in item):
            raise ContractError("family_id must occur only for versioned escalation families")
        family_id = _token(item["family_id"], "observation.family_id") if "family_id" in item else None
        configuration = _enum(
            item["configuration"], {"interesting", "ordinary", "unknown"}, "observation.configuration"
        )
        evidence_ids = _evidence_ids(item["evidence_ids"], "observation.evidence_ids")
        requirements = _requirements(item["requirements"])
        if "canary" in item and not canary_assertions:
            raise ContractError("canary lacks declared bridge capability")
        canary = _canary(item["canary"]) if "canary" in item else None
        decision = _decision(host, requirements)
        if decision != "selected":
            classification = "not_evaluated"
        elif canary:
            classification = "reported_canary_crossing" if canary["case"] == "positive" else "reported_canary_blocked"
        else:
            classification = {
                "interesting": "configuration_candidate",
                "ordinary": "ordinary_configuration",
                "unknown": "insufficient_evidence",
            }[configuration]
        result: dict[str, Any] = {
            "id": obs_id,
            "surface": surface,
            "decision": decision,
            "classification": classification,
            "evidence_ids": evidence_ids,
            "requirements": requirements,
        }
        if family_id:
            result["family_id"] = family_id
        if canary:
            result["canary_case"] = canary["case"]
            result["canary_resource_id"] = canary["resource_id"]
            result["canary_evidence_ids"] = canary["evidence_ids"]
            result["cleanup_reported"] = True
        results.append(result)
    counts = Counter(result["classification"] for result in results)
    return {
        "schema_version": "windows-1.0",
        "mode": "native_bridge_import" if bridge_mode == "native_windows_bridge" else "offline_import",
        "source": {"kind": source_kind, "id": source_id},
        "bridge": {
            "mode": bridge_mode,
            "platform": "windows",
            "capabilities": capabilities,
            "canary_assertions": canary_assertions,
        },
        "host": host,
        "coverage": coverage,
        "observations": results,
        "counts": {name: counts[name] for name in CLASSIFICATIONS},
    }
