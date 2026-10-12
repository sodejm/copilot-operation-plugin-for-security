#!/usr/bin/env python3
"""Validate bounded package data without importing or executing assessment code."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_KEYS = {
    "$id", "$schema", "title", "description", "type", "const", "enum", "required",
    "properties", "additionalProperties", "items", "oneOf", "minLength", "maxLength",
    "pattern", "minItems", "maxItems", "uniqueItems", "minimum", "maximum",
}
SUPPORTED_PATTERNS = {
    "^[a-z0-9]+(?:-[a-z0-9]+)*$", "^[a-z0-9]+(-[a-z0-9]+)*$",
    "^SCN-[A-Za-z0-9_-]+$", r"\S",
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

    value = json.loads(read_text(path, limit), object_pairs_hook=pairs,
                       parse_constant=invalid_constant)
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


def check_schema(value, schema):
    """Check the small, explicit JSON Schema vocabulary used by case definitions."""
    if not isinstance(schema, dict) or set(schema) - SCHEMA_KEYS:
        raise PackageError("Unsupported case schema")
    if "oneOf" in schema:
        matches = 0
        for branch in schema["oneOf"]:
            try:
                check_schema(value, branch)
                matches += 1
            except PackageError:
                pass
        if matches != 1:
            raise PackageError("Invalid schema alternative")
    types = {
        "object": dict, "array": list, "string": str, "integer": int,
        "number": (int, float), "boolean": bool, "null": type(None),
    }
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(type(value) in (types[name] if isinstance(types[name], tuple)
                                  else (types[name],)) for name in names):
            raise PackageError("Invalid case field type")
    if "const" in schema and (type(value) is not type(schema["const"])
                              or value != schema["const"]):
        raise PackageError("Invalid constant")
    if "enum" in schema and not any(type(value) is type(item) and value == item
                                    for item in schema["enum"]):
        raise PackageError("Invalid enumeration")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if set(schema.get("required", ())) - value.keys():
            raise PackageError("Missing case field")
        if schema.get("additionalProperties") is False and value.keys() - properties.keys():
            raise PackageError("Unknown case field")
        for key in value.keys() & properties.keys():
            check_schema(value[key], properties[key])
    elif isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            raise PackageError("Invalid array size")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True)
                                             for item in value}) != len(value):
            raise PackageError("Duplicate array item")
        if "items" in schema:
            for item in value:
                check_schema(item, schema["items"])
    elif isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
            raise PackageError("Invalid string size")
        if "pattern" in schema:
            if schema["pattern"] not in SUPPORTED_PATTERNS:
                raise PackageError("Unsupported string pattern")
            if re.search(schema["pattern"], value) is None:
                raise PackageError("Invalid string pattern")
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
    schema = load_json(PLUGIN_ROOT / "schemas" / schema_name)
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
        if (len(case["attempts"]) != len(case["expected_decisions"])
                or len(case["attempts"]) != len(case["expected_reasons"])
                or case["expected_effect_count"] > len(case["attempts"])
                or (case.get("surface", "local_synthetic_fixture") == "unsupported_provider_surface"
                    and case.get("expected_outcome", "pass") != "unsupported")):
            raise PackageError("Inconsistent authorization definition")
        definitions.append((
            case["grant"], case["flow"],
            [{"peer_action": "trusted_forward", "fault_mode": "none", **attempt}
             for attempt in case["attempts"]],
            case["expected_decisions"], case["expected_reasons"], case["expected_effect_count"],
            case.get("surface", "local_synthetic_fixture"), case.get("expected_outcome", "pass"),
        ))
    required = []
    for grant, principal, flow, tenant in (
        ("delegated-write", "principal-alice", "delegated", "tenant-contoso-01"),
        ("delegated-write-fabrikam", "principal-bob", "delegated", "tenant-fabrikam-02"),
        ("autonomous-write", "service-scheduler", "autonomous", "tenant-contoso-01"),
    ):
        attempt = {
            "principal": principal, "agent": "agent-worker",
            "downstream_service": "service-canary", "audience": "mcp://auth-fixture",
            "tenant": tenant, "resource": "res-canary", "operation": "write",
            "scopes": ["canary:write"], "depth": 1, "tick": 1, "tool": "canary/write",
            "peer_action": "trusted_forward", "fault_mode": "none",
        }
        required.append((grant, flow, [attempt], ["allowed"], ["allowed"], 1,
                         "local_synthetic_fixture", "pass"))
        if flow == "delegated":
            other = "tenant-fabrikam-02" if tenant == "tenant-contoso-01" else "tenant-contoso-01"
            required.append((grant, flow, [{**attempt, "tenant": other}], ["denied"],
                             ["tenant_mismatch"], 0, "local_synthetic_fixture", "pass"))
        if grant == "delegated-write":
            for action, reason in (
                ("mutate_tenant", "tenant_mismatch"), ("omit_tenant", "missing_tenant"),
                ("mutate_operation", "operation_mismatch"),
                ("substitute_receipt", "unrecognized_grant_or_actor"),
            ):
                required.append((grant, flow, [{**attempt, "peer_action": action}], ["denied"],
                                 [reason], 0, "local_synthetic_fixture", "pass"))
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
        PLUGIN_ROOT / "schemas" / "auth-report.schema.json",
    ]

    try:
        for path in json_files:
            if not isinstance(load_json(path), dict):
                raise PackageError("Invalid package configuration")
        for name in ("foundry-agent-review", "ai-agent-mcp-laboratories"):
            content = read_text(PLUGIN_ROOT / "skills" / name / "SKILL.md")
            if not content.startswith(f"---\nname: {name}\n"):
                raise PackageError("Invalid skill frontmatter")
        scenarios = load_cases("scenarios", "scenario.schema.json", "scenario_id", 6)
        labs = load_cases("lab_cases", "lab-case.schema.json", "case_id", 10)
        auth = load_cases("auth_cases", "auth-case.schema.json", "case_id", 9)
        check_auth_coverage(auth)
    except (PackageError, OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        print("FAIL: Invalid, missing, or unsupported package data; assessment code was not loaded.",
              file=sys.stderr)
        return 1
    print(f"  OK: Validated {len(json_files)} package configuration and schema files.")
    print("  OK: Validated skill definitions and frontmatter.")
    print(f"  OK: Validated {len(scenarios)} scenario, {len(labs)} laboratory, "
          f"and {len(auth)} authorization case definitions.")
    print("[validate_package] Data checks passed; runtime behavior requires separate observed execution.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
