"""Validate local host assessment exports and classify only reported evidence.

No collector or live host access exists in this module. The caller supplies an
already-produced local export; canary results remain source assertions.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

MAX_INPUT_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_OBSERVATIONS = 256
MAX_EVIDENCE_IDS = 32
SURFACES = (
    "permissions",
    "services",
    "scheduled_tasks",
    "capabilities",
    "sudo",
    "suid",
    "credential_exposure",
    "container_context",
)
PROTECTIONS = ("selinux", "apparmor", "no_new_privs", "seccomp", "user_namespaces")
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
CLASSIFICATIONS = (
    "reported_canary_crossing",
    "reported_canary_blocked",
    "configuration_candidate",
    "ordinary_configuration",
    "insufficient_evidence",
    "not_evaluated",
)


class ContractError(ValueError):
    """The local export does not satisfy the versioned import contract."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ContractError("nonfinite JSON number")


def _check_json_depth(data: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in data:
        if in_string:
            if escaped:
                escaped = False
            elif char == 92:  # backslash
                escaped = True
            elif char == 34:  # quote
                in_string = False
        elif char == 34:
            in_string = True
        elif char in (91, 123):  # opening bracket or brace
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ContractError("JSON nesting exceeds parser limit")
        elif char in (93, 125):
            depth -= 1


def load_report_bytes(data: bytes) -> dict[str, Any]:
    """Read a bounded JSON export and return its deterministic assessment."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise ContractError("input must be at most 1 MiB of JSON bytes")
    _check_json_depth(data)
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("malformed UTF-8 JSON") from exc
    except RecursionError as exc:
        raise ContractError("JSON nesting exceeds parser limit") from exc
    return assess_document(payload)


def _exact_keys(value: Any, required: set[str], where: str, optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - (required | (optional or set())) or required - set(value):
        raise ContractError(f"{where} has missing or unsupported fields")
    return value


def _enum(value: Any, allowed: set[str], where: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ContractError(f"{where} has unsupported state")
    return value


def _token(value: Any, where: str, *, version: bool = False, unknown: bool = False) -> str:
    pattern = VERSION_PATTERN if version else ID_PATTERN
    if not isinstance(value, str) or not pattern.fullmatch(value) or (value == "unknown" and not unknown):
        raise ContractError(f"{where} must be a bounded opaque identifier")
    return value


def _evidence_ids(value: Any, where: str, *, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= MAX_EVIDENCE_IDS:
        raise ContractError(f"{where} requires bounded evidence IDs")
    result = [_token(item, where) for item in value]
    if len(result) != len(set(result)):
        raise ContractError(f"{where} has duplicate evidence IDs")
    return result


def _host(value: Any) -> dict[str, Any]:
    host = _exact_keys(
        value, {"kernel_release", "distribution_id", "distribution_version", "namespace", "protections"}, "host"
    )
    protections = _exact_keys(host["protections"], set(PROTECTIONS), "host.protections")
    states = {
        name: _enum(
            protections[name], {"enabled", "disabled", "enforcing", "permissive", "unknown"}, f"host.protections.{name}"
        )
        for name in PROTECTIONS
    }
    return {
        "kernel_release": _token(host["kernel_release"], "host.kernel_release", version=True, unknown=True),
        "distribution_id": _token(host["distribution_id"], "host.distribution_id", unknown=True),
        "distribution_version": _token(
            host["distribution_version"], "host.distribution_version", version=True, unknown=True
        ),
        "namespace": _enum(host["namespace"], {"host", "container", "unknown"}, "host.namespace"),
        "protections": states,
    }


def _requirements(value: Any) -> dict[str, Any]:
    req = _exact_keys(
        value, {"kernel_release", "distribution_id", "distribution_version", "namespace", "protections"}, "requirements"
    )
    protections = req["protections"]
    if not isinstance(protections, dict) or set(protections) - set(PROTECTIONS):
        raise ContractError("requirements.protections has unsupported fields")
    states = {
        name: _enum(state, {"enabled", "disabled", "enforcing", "permissive"}, f"requirements.protections.{name}")
        for name, state in sorted(protections.items())
    }
    return {
        "kernel_release": _token(req["kernel_release"], "requirements.kernel_release", version=True),
        "distribution_id": _token(req["distribution_id"], "requirements.distribution_id"),
        "distribution_version": _token(req["distribution_version"], "requirements.distribution_version", version=True),
        "namespace": _enum(req["namespace"], {"host", "container"}, "requirements.namespace"),
        "protections": states,
    }


def _canary(value: Any) -> dict[str, Any]:
    fields = {
        "case",
        "resource_id",
        "disposable_host",
        "assessment_owned",
        "before_access",
        "after_access",
        "evidence_ids",
        "cleanup_verified",
    }
    canary = _exact_keys(value, fields, "canary")
    case = _enum(canary["case"], {"positive", "negative", "fixed"}, "canary.case")
    for name in ("disposable_host", "assessment_owned", "cleanup_verified"):
        if canary[name] is not True:
            raise ContractError(f"canary.{name} must be asserted true")
    before = _enum(canary["before_access"], {"denied", "granted"}, "canary.before_access")
    after = _enum(canary["after_access"], {"denied", "granted"}, "canary.after_access")
    if before != "denied" or after != ("granted" if case == "positive" else "denied"):
        raise ContractError("canary access sequence contradicts its case")
    return {
        "case": case,
        "resource_id": _token(canary["resource_id"], "canary.resource_id"),
        "evidence_ids": _evidence_ids(canary["evidence_ids"], "canary.evidence_ids", minimum=3),
    }


def _decision(host: dict[str, Any], req: dict[str, Any]) -> str:
    actual = [host[key] for key in ("kernel_release", "distribution_id", "distribution_version", "namespace")]
    expected = [req[key] for key in ("kernel_release", "distribution_id", "distribution_version", "namespace")]
    actual.extend(host["protections"][name] for name in req["protections"])
    expected.extend(req["protections"].values())
    if any(observed != "unknown" and observed != needed for observed, needed in zip(actual, expected, strict=True)):
        return "inapplicable"
    if "unknown" in actual:
        return "unresolved"
    return "selected"


def assess_document(payload: dict[str, Any]) -> dict[str, Any]:
    """Classify an export without treating imported claims as live verification."""
    if isinstance(payload, dict) and payload.get("schema_version") == "windows-1.0":
        from .windows import assess_windows_document

        return assess_windows_document(payload)
    document = _exact_keys(
        payload, {"schema_version", "source_kind", "source_id", "host", "coverage", "observations"}, "document"
    )
    if document["schema_version"] != "1.0":
        raise ContractError("unsupported schema version")
    source_kind = _enum(document["source_kind"], {"synthetic_lab", "operator_export"}, "source_kind")
    source_id = _token(document["source_id"], "source_id")
    host = _host(document["host"])
    raw_coverage = _exact_keys(document["coverage"], set(SURFACES), "coverage")
    coverage = {
        surface: _enum(
            raw_coverage[surface], {"assessed", "not_assessed", "unsupported", "access_denied"}, f"coverage.{surface}"
        )
        for surface in SURFACES
    }
    observations = document["observations"]
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise ContractError("observations must be a bounded list")

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in observations:
        item = _exact_keys(
            raw, {"id", "surface", "configuration", "evidence_ids", "requirements"}, "observation", {"canary"}
        )
        obs_id = _token(item["id"], "observation.id")
        if obs_id in seen:
            raise ContractError("duplicate observation ID")
        seen.add(obs_id)
        surface = _enum(item["surface"], set(SURFACES), "observation.surface")
        if coverage[surface] != "assessed":
            raise ContractError("observation is present on a surface without assessed coverage")
        config = _enum(item["configuration"], {"interesting", "ordinary", "unknown"}, "observation.configuration")
        evidence_ids = _evidence_ids(item["evidence_ids"], "observation.evidence_ids")
        req = _requirements(item["requirements"])
        canary = _canary(item["canary"]) if "canary" in item else None
        decision = _decision(host, req)
        if decision != "selected":
            classification = "not_evaluated"
        elif canary:
            classification = "reported_canary_crossing" if canary["case"] == "positive" else "reported_canary_blocked"
        else:
            classification = {
                "interesting": "configuration_candidate",
                "ordinary": "ordinary_configuration",
                "unknown": "insufficient_evidence",
            }[config]
        result: dict[str, Any] = {
            "id": obs_id,
            "surface": surface,
            "decision": decision,
            "classification": classification,
            "evidence_ids": evidence_ids,
            "requirements": req,
        }
        if canary:
            result["canary_case"] = canary["case"]
            result["canary_resource_id"] = canary["resource_id"]
            result["canary_evidence_ids"] = canary["evidence_ids"]
            result["cleanup_reported"] = True
        results.append(result)
    counts = Counter(result["classification"] for result in results)
    return {
        "schema_version": "1.0",
        "mode": "offline_import",
        "source": {"kind": source_kind, "id": source_id},
        "host": host,
        "coverage": coverage,
        "observations": results,
        "counts": {name: counts[name] for name in CLASSIFICATIONS},
    }
