#!/usr/bin/env python3
"""Validate bounded package data without importing or executing assessment code."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import sys
from datetime import date
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_KEYS = {
    "$id",
    "$schema",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "patternProperties",
    "additionalProperties",
    "maxProperties",
    "items",
    "oneOf",
    "anyOf",
    "minLength",
    "maxLength",
    "pattern",
    "format",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minimum",
    "maximum",
}
SUPPORTED_PATTERNS = {
    "^[a-z0-9]+(?:-[a-z0-9]+)*$",
    "^[a-z0-9]+(-[a-z0-9]+)*$",
    "^SCN-[A-Za-z0-9_-]+$",
    r"\S",
    "^[a-f0-9]{64}$",
    "^[0-9a-f]{64}$",
    "^CANARY_[A-Z0-9_]+$",
    "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    "^fixture-[A-Za-z0-9._-]+$",
    "^synthetic-[A-Za-z0-9._-]+$",
    r"^https://[A-Za-z0-9.-]+\.invalid(?:/[A-Za-z0-9._/-]*)?$",
    "^case-[0-9a-f]{64}$",
}
SCHEMA_TYPES = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "null": (type(None),),
}


class PackageError(ValueError):
    """Invalid or unsupported package data; messages never contain input values."""


def read_text(path: Path, limit: int = 1024 * 1024) -> str:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise PackageError("Symlink package input")
        if component == PLUGIN_ROOT:
            break
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise PackageError("Unbounded package input")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise PackageError("Unbounded package input")
    return content.decode("utf-8")


def load_json(path: Path, limit: int = 1024 * 1024):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PackageError("Duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise PackageError("Non-finite JSON value")

    value = json.loads(read_text(path, limit), object_pairs_hook=pairs, parse_constant=invalid_constant)
    stack, visited = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        visited += 1
        if depth > 40 or visited > 10000:
            raise PackageError("Unbounded JSON structure")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in (*item.keys(), *item.values()))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, float) and not math.isfinite(item):
            raise PackageError("Non-finite JSON value")
    return value


def admit_schema(schema):
    """Admit every schema node, including unused definitions, before checking data."""
    if (
        not isinstance(schema, dict)
        or schema.get("type") != "object"
        or not schema.get("properties")
        or not schema.get("required")
        or schema.get("additionalProperties") is not False
    ):
        raise PackageError("Invalid package schema root")
    definitions = schema.get("$defs", {})
    stack, visited = [(schema, 0)], 0
    while stack:
        node, depth = stack.pop()
        visited += 1
        if (
            not isinstance(node, dict)
            or not node
            or set(node) - SCHEMA_KEYS
            or not set(node) & {"type", "const", "enum", "properties", "$ref", "oneOf", "anyOf"}
            or depth > 40
            or visited > 10000
        ):
            raise PackageError("Unsupported package schema")
        for key in ("$id", "$schema", "title", "description"):
            if key in node and (not isinstance(node[key], str) or not node[key]):
                raise PackageError("Invalid schema metadata")
        if "type" in node:
            names = node["type"] if isinstance(node["type"], list) else [node["type"]]
            if (
                not names
                or any(not isinstance(name, str) or name not in SCHEMA_TYPES for name in names)
                or len(set(names)) != len(names)
            ):
                raise PackageError("Unsupported schema type")
        for key in ("properties", "$defs", "patternProperties"):
            if key in node:
                if not isinstance(node[key], dict) or any(not name for name in node[key]):
                    raise PackageError("Invalid schema properties")
                if key == "patternProperties" and set(node[key]) - SUPPORTED_PATTERNS:
                    raise PackageError("Unsupported property-name pattern")
                stack.extend((child, depth + 1) for child in node[key].values())
        if "$defs" in node and node is not schema:
            raise PackageError("Unsupported nested schema definitions")
        if "required" in node:
            required = node["required"]
            if (
                not isinstance(required, list)
                or any(not isinstance(name, str) or not name for name in required)
                or len(set(required)) != len(required)
                or ("properties" in node and set(required) - node["properties"].keys())
            ):
                raise PackageError("Invalid required schema fields")
        if "enum" in node and (not isinstance(node["enum"], list) or not node["enum"]):
            raise PackageError("Invalid schema enumeration")
        if "additionalProperties" in node:
            additional = node["additionalProperties"]
            if isinstance(additional, dict):
                stack.append((additional, depth + 1))
            elif type(additional) is not bool:
                raise PackageError("Invalid additional properties schema")
        if "items" in node:
            stack.append((node["items"], depth + 1))
        for key in ("oneOf", "anyOf"):
            if key in node:
                if not isinstance(node[key], list) or not node[key]:
                    raise PackageError("Invalid schema alternatives")
                stack.extend((child, depth + 1) for child in node[key])
        if "pattern" in node and (not isinstance(node["pattern"], str) or node["pattern"] not in SUPPORTED_PATTERNS):
            raise PackageError("Unsupported schema string pattern")
        if "format" in node and node["format"] != "date":
            raise PackageError("Unsupported schema format")
        if "maxProperties" in node and (
            type(node["maxProperties"]) is not int or not 0 <= node["maxProperties"] <= 1000
        ):
            raise PackageError("Invalid property count bound")
        if "uniqueItems" in node and type(node["uniqueItems"]) is not bool:
            raise PackageError("Invalid schema uniqueness constraint")
        for low, high, integer in (
            ("minLength", "maxLength", True),
            ("minItems", "maxItems", True),
            ("minimum", "maximum", False),
        ):
            for key in (low, high):
                if key in node:
                    bound = node[key]
                    if (
                        type(bound) not in ((int,) if integer else (int, float))
                        or (integer and bound < 0)
                        or (type(bound) is float and not math.isfinite(bound))
                    ):
                        raise PackageError("Invalid schema bounds")
            if low in node and high in node and node[low] > node[high]:
                raise PackageError("Inconsistent schema bounds")
        if "$ref" in node:
            reference = node["$ref"]
            if (
                not isinstance(reference, str)
                or not reference.startswith("#/$defs/")
                or reference[8:] not in definitions
            ):
                raise PackageError("Invalid local schema reference")
    # Resolve the complete graph, rejecting cycles and excessive expansion.
    stack, visited = [(schema, (), 0)], 0
    while stack:
        node, ancestry, depth = stack.pop()
        visited += 1
        if id(node) in ancestry or depth > 40 or visited > 10000:
            raise PackageError("Unbounded schema reference graph")
        ancestry = (*ancestry, id(node))
        children = list(node.get("properties", {}).values()) + list(node.get("$defs", {}).values())
        children += list(node.get("patternProperties", {}).values())
        children += node.get("oneOf", []) + node.get("anyOf", [])
        if "items" in node:
            children.append(node["items"])
        if isinstance(node.get("additionalProperties"), dict):
            children.append(node["additionalProperties"])
        if "$ref" in node:
            children.append(definitions[node["$ref"][8:]])
        stack.extend((child, ancestry, depth + 1) for child in children)
    return schema


def check_schema(value, schema, root=None):
    """Check data against the admitted, explicit package schema vocabulary."""
    root = schema if root is None else root
    if "$ref" in schema:
        check_schema(value, root["$defs"][schema["$ref"][8:]], root)
    for keyword in ("oneOf", "anyOf"):
        if keyword not in schema:
            continue
        matches = 0
        for branch in schema[keyword]:
            try:
                check_schema(value, branch, root)
                matches += 1
            except PackageError:
                pass
        if (keyword == "oneOf" and matches != 1) or (keyword == "anyOf" and matches == 0):
            raise PackageError("Invalid schema alternative")
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(type(value) in SCHEMA_TYPES[name] for name in names):
            raise PackageError("Invalid case field type")
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        raise PackageError("Invalid constant")
    if "enum" in schema and not any(type(value) is type(item) and value == item for item in schema["enum"]):
        raise PackageError("Invalid enumeration")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        patterns = schema.get("patternProperties", {})
        if set(schema.get("required", ())) - value.keys():
            raise PackageError("Missing case field")
        if len(value) > schema.get("maxProperties", len(value)):
            raise PackageError("Too many object fields")
        for key in value:
            if key in properties:
                check_schema(value[key], properties[key], root)
            matching = [child for pattern, child in patterns.items() if re.search(pattern, key)]
            for child in matching:
                check_schema(value[key], child, root)
            if key in properties or matching:
                continue
            if schema.get("additionalProperties") is False:
                raise PackageError("Unknown case field")
            if isinstance(schema.get("additionalProperties"), dict):
                check_schema(value[key], schema["additionalProperties"], root)
    elif isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            raise PackageError("Invalid array size")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise PackageError("Duplicate array item")
        if "items" in schema:
            for item in value:
                check_schema(item, schema["items"], root)
    elif isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
            raise PackageError("Invalid string size")
        if "pattern" in schema:
            if not isinstance(schema["pattern"], str) or schema["pattern"] not in SUPPORTED_PATTERNS:
                raise PackageError("Unsupported string pattern")
            if re.search(schema["pattern"], value) is None:
                raise PackageError("Invalid string pattern")
        if schema.get("format") == "date":
            try:
                if date.fromisoformat(value).isoformat() != value:
                    raise PackageError("Invalid date")
            except ValueError as exc:
                raise PackageError("Invalid date") from exc
    elif type(value) in (int, float):
        if not schema.get("minimum", -math.inf) <= value <= schema.get("maximum", math.inf):
            raise PackageError("Invalid numeric range")


def load_cases(directory: str, schema_name: str, identity: str, minimum: int):
    folder = PLUGIN_ROOT / directory
    if not folder.is_dir() or folder.is_symlink():
        raise PackageError("Missing case directory")
    files = []
    for path in folder.iterdir():
        if path.suffix == ".json":
            files.append(path)
            if len(files) > 100:
                raise PackageError("Too many case definitions")
    if len(files) < minimum:
        raise PackageError("Missing case definitions")
    schema = admit_schema(load_json(PLUGIN_ROOT / "schemas" / schema_name))
    cases, identities = [], set()
    for path in sorted(files):
        case = load_json(path, 64 * 1024)
        check_schema(case, schema)
        if case[identity] in identities:
            raise PackageError("Duplicate case identity")
        identities.add(case[identity])
        cases.append(case)
    return cases


def check_auth_coverage(cases):
    definitions = []
    for case in cases:
        if (
            len(case["attempts"]) != len(case["expected_decisions"])
            or len(case["attempts"]) != len(case["expected_reasons"])
            or case["expected_effect_count"] > len(case["attempts"])
            or (
                case.get("surface", "local_synthetic_fixture") == "unsupported_provider_surface"
                and case.get("expected_outcome", "pass") != "unsupported"
            )
        ):
            raise PackageError("Inconsistent authorization definition")
        definitions.append(
            (
                case["grant"],
                case["flow"],
                [{"peer_action": "trusted_forward", "fault_mode": "none", **attempt} for attempt in case["attempts"]],
                case["expected_decisions"],
                case["expected_reasons"],
                case["expected_effect_count"],
                case.get("surface", "local_synthetic_fixture"),
                case.get("expected_outcome", "pass"),
            )
        )
    required = []
    for grant, principal, flow, tenant in (
        ("delegated-write", "principal-alice", "delegated", "tenant-contoso-01"),
        ("delegated-write-fabrikam", "principal-bob", "delegated", "tenant-fabrikam-02"),
        ("autonomous-write", "service-scheduler", "autonomous", "tenant-contoso-01"),
    ):
        attempt = {
            "principal": principal,
            "agent": "agent-worker",
            "downstream_service": "service-canary",
            "audience": "mcp://auth-fixture",
            "tenant": tenant,
            "resource": "res-canary",
            "operation": "write",
            "scopes": ["canary:write"],
            "depth": 1,
            "tick": 1,
            "tool": "canary/write",
            "peer_action": "trusted_forward",
            "fault_mode": "none",
        }
        required.append((grant, flow, [attempt], ["allowed"], ["allowed"], 1, "local_synthetic_fixture", "pass"))
        if flow == "delegated":
            other = "tenant-fabrikam-02" if tenant == "tenant-contoso-01" else "tenant-contoso-01"
            required.append(
                (
                    grant,
                    flow,
                    [{**attempt, "tenant": other}],
                    ["denied"],
                    ["tenant_mismatch"],
                    0,
                    "local_synthetic_fixture",
                    "pass",
                )
            )
        if grant == "delegated-write":
            for action, reason in (
                ("mutate_tenant", "tenant_mismatch"),
                ("omit_tenant", "missing_tenant"),
                ("mutate_operation", "operation_mismatch"),
                ("substitute_receipt", "unrecognized_grant_or_actor"),
            ):
                required.append(
                    (
                        grant,
                        flow,
                        [{**attempt, "peer_action": action}],
                        ["denied"],
                        [reason],
                        0,
                        "local_synthetic_fixture",
                        "pass",
                    )
                )
    if any(probe not in definitions for probe in required):
        raise PackageError("Missing required default authorization coverage")


def validate() -> int:
    print("[validate_package] Checking bounded Foundry Agent Harness package data...")

    # 1. Check manifests and metadata
    json_files = [
        PLUGIN_ROOT / "package.json",
        PLUGIN_ROOT / "plugin.json",
        PLUGIN_ROOT / ".claude-plugin" / "plugin.json",
        PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
        PLUGIN_ROOT / "org.cops" / "prerequisites.json",
        PLUGIN_ROOT / "schemas" / "scenario.schema.json",
        PLUGIN_ROOT / "schemas" / "report.schema.json",
        PLUGIN_ROOT / "schemas" / "lab-case.schema.json",
        PLUGIN_ROOT / "schemas" / "lab-report.schema.json",
        PLUGIN_ROOT / "schemas" / "auth-case.schema.json",
        PLUGIN_ROOT / "schemas" / "auth-adapter.schema.json",
        PLUGIN_ROOT / "schemas" / "auth-evidence.schema.json",
        PLUGIN_ROOT / "schemas" / "auth-normalized-observation.schema.json",
        PLUGIN_ROOT / "schemas" / "auth-report.schema.json",
        PLUGIN_ROOT / "schemas" / "provider-plan.schema.json",
        PLUGIN_ROOT / "schemas" / "provider-cases.schema.json",
        PLUGIN_ROOT / "schemas" / "provider-report.schema.json",
    ]

    try:
        for path in json_files:
            value = load_json(path)
            if not isinstance(value, dict):
                raise PackageError("Invalid package configuration")
            if path.parent.name == "schemas":
                admit_schema(value)
        # The response envelope uses conditionals outside this data-only gate's admitted
        # schema vocabulary. Check bounded syntax here; the offline runner checks it fully.
        load_json(PLUGIN_ROOT / "schemas" / "provider-response.schema.json")
        report_schema = admit_schema(load_json(PLUGIN_ROOT / "schemas" / "auth-report.schema.json"))
        normalized_schema = load_json(PLUGIN_ROOT / "schemas" / "auth-normalized-observation.schema.json")
        embedded_schema = report_schema["$defs"]["normalized_observation"]
        if embedded_schema != {
            key: value for key, value in normalized_schema.items() if key not in {"$schema", "title"}
        }:
            raise PackageError("Normalized observation schema differs from report definition")
        for name in ("auth-authorized.json", "auth-denied.json", "auth-inconclusive.json"):
            check_schema(load_json(PLUGIN_ROOT / "examples" / name), report_schema)
        for name in ("foundry-agent-review", "ai-agent-mcp-laboratories", "ai-provider-assessment"):
            content = read_text(PLUGIN_ROOT / "skills" / name / "SKILL.md")
            if not content.startswith(f"---\nname: {name}\n"):
                raise PackageError("Invalid skill frontmatter")
        scenarios = load_cases("scenarios", "scenario.schema.json", "scenario_id", 6)
        labs = load_cases("lab_cases", "lab-case.schema.json", "case_id", 10)
        auth = load_cases("auth_cases", "auth-case.schema.json", "case_id", 9)
        check_auth_coverage(auth)
        provider_plan = load_json(PLUGIN_ROOT / "provider_fixtures" / "plan.json")
        provider_cases = load_json(PLUGIN_ROOT / "provider_fixtures" / "cases.json")
        check_schema(provider_plan, admit_schema(load_json(PLUGIN_ROOT / "schemas" / "provider-plan.schema.json")))
        check_schema(provider_cases, admit_schema(load_json(PLUGIN_ROOT / "schemas" / "provider-cases.schema.json")))
        case_ids = [case["case_id"] for case in provider_cases["cases"]]
        if len(case_ids) < 14 or len(case_ids) != len(set(case_ids)):
            raise PackageError("Missing or duplicate provider fixture case")
    except (PackageError, OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        print("FAIL: Invalid, missing, or unsupported package data; assessment code was not loaded.", file=sys.stderr)
        return 1
    print(f"  OK: Validated {len(json_files)} package configuration and schema files.")
    print("  OK: Validated skill definitions and frontmatter.")
    print(
        f"  OK: Validated {len(scenarios)} scenario, {len(labs)} laboratory, "
        f"and {len(auth)} authorization case definitions."
    )
    print(f"  OK: Validated {len(case_ids)} provider fixture cases as data.")
    print("[validate_package] Data checks passed; runtime behavior requires separate observed execution.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
