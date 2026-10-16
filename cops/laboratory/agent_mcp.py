"""Trusted, data-only planning for the synthetic agent/MCP authorization lab.

The executable laboratory sources are read as bytes here.  Importing this module
must never import an executable laboratory source before its signed approval is
verified and consumed by the bootstrap.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cops.contracts import ActionPlan
from cops.evidence.canonical import EvidenceError, canonical, digest
from cops.evidence.canonical import decode_json as _decode_json


class JSONInputError(ValueError):
    """A bounded, regular input file or its JSON content is invalid."""


SOURCE_FILES = (
    "auth_approval.py",
    "auth_effect_observer.py",
    "auth_fixture_server.py",
    "auth_laboratory.py",
    "auth_peer_fixture.py",
    "bounded_json.py",
    "laboratory.py",
)
ADAPTER_ID = "local-synthetic-mcp-auth-fixture"
SCENARIO_ID = "COPS-E16.01"
TARGET = "local-synthetic-agent-mcp-authorization-fixture"
SPECIALIST_ID = "cops-agent-mcp-authorization-lab"
PROTOCOL_VERSION = "2025-11-25"
SERVER_INFO = {"name": "cops-auth-fixture", "version": "1"}
TEST_IDENTITY = "synthetic-fixture-runner"
TOOLS = ("canary/read", "canary/write")
FLOWS = ("delegated", "autonomous")
FAULT_MODES = ("none", "hung_server", "missing_identity_telemetry", "observer_failure", "lost_response_after_effect")
PEER_ACTIONS = ("trusted_forward", "mutate_tenant", "omit_tenant", "mutate_operation", "substitute_receipt")
GRANTS = (
    "delegated-write",
    "delegated-write-fabrikam",
    "autonomous-write",
    "one-time-write",
    "reusable-write",
    "expired-write",
    "revoked-write",
    "read-only",
    "read-only-fabrikam",
)
SYNTHETIC_GRANT_ALIASES = (*GRANTS, "receipt-approved-synthetic")
ARGUMENT_ALIASES = {
    "grant": frozenset(SYNTHETIC_GRANT_ALIASES),
    "flow": frozenset(FLOWS),
    "principal": frozenset(("principal-alice", "principal-bob", "service-scheduler")),
    "agent": frozenset(("agent-worker", "agent-shadow")),
    "downstream_service": frozenset(("service-canary", "service-shadow")),
    "audience": frozenset(("mcp://auth-fixture", "mcp://shadow")),
    "tenant": frozenset(("tenant-contoso-01", "tenant-fabrikam-02")),
    "resource": frozenset(("res-canary", "res-other")),
    "operation": frozenset(("read", "write")),
    "fault_mode": frozenset(FAULT_MODES),
}
SCOPES = frozenset(("canary:read", "canary:write", "canary:admin"))
ID_PATTERN = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_CASE_REQUIRED = frozenset(
    (
        "schema_version",
        "case_id",
        "title",
        "grant",
        "flow",
        "attempts",
        "expected_decisions",
        "expected_reasons",
        "expected_effect_count",
    )
)
_CASE_OPTIONAL = frozenset(("surface", "expected_outcome"))
_ATTEMPT_REQUIRED = frozenset(
    (
        "principal",
        "agent",
        "downstream_service",
        "audience",
        "resource",
        "operation",
        "scopes",
        "depth",
        "tick",
        "tool",
    )
)
_ATTEMPT_OPTIONAL = frozenset(("tenant", "peer_action", "fault_mode"))
DECISIONS = frozenset(("allowed", "denied", "inconclusive"))
REASONS = frozenset(
    (
        "allowed",
        "missing_context",
        "unrecognized_grant_or_actor",
        "expired_grant",
        "revoked_grant",
        "one_time_replay",
        "flow_mismatch",
        "principal_or_agent_binding",
        "downstream_service_mismatch",
        "audience_mismatch",
        "tenant_mismatch",
        "missing_tenant",
        "resource_mismatch",
        "delegation_depth_exceeded",
        "tool_not_permitted",
        "operation_mismatch",
        "scope_mismatch",
    )
)
SURFACES = frozenset(("local_synthetic_fixture", "unsupported_provider_surface"))
OUTCOMES = frozenset(("pass", "fail", "inconclusive", "unsupported"))


def read_regular_file(path: str | Path, *, max_bytes: int) -> bytes:
    """Read bounded bytes without following links or blocking on special files."""
    descriptor = None
    try:
        initial = os.lstat(path)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > max_bytes:
            raise JSONInputError("Input must be a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
            or opened.st_size > max_bytes
        ):
            raise JSONInputError("Input must be a bounded regular file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise JSONInputError("Input exceeds its byte limit")
    except OSError as exc:
        raise JSONInputError("Input must be a readable bounded regular file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def decode_json(raw: bytes, *, max_bytes: int = 1048576) -> Any:
    try:
        return _decode_json(raw, max_bytes=max_bytes)
    except EvidenceError as exc:
        raise JSONInputError("Input must contain bounded strict JSON") from exc


def _fields(value: Any, required: frozenset[str], optional: frozenset[str]) -> None:
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("Authorization case contains missing or unexpected fields")


def _member(value: Any, allowed: Iterable[str]) -> bool:
    return type(value) is str and value in allowed


def normalize_case_inputs(cases: Iterable[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    """Validate the complete case contract without loading executable sources."""
    rows = []
    seen = set()
    for case in cases:
        if len(rows) >= 100:
            raise ValueError("Authorization laboratory supports at most 100 cases")
        _fields(case, _CASE_REQUIRED, _CASE_OPTIONAL)
        if case["schema_version"] != "cops.agent-mcp-auth-case/v1":
            raise ValueError("Unsupported authorization case schema")
        case_id = case["case_id"]
        if type(case_id) is not str or len(case_id) > 64 or re.fullmatch(ID_PATTERN, case_id) is None:
            raise ValueError("Authorization case identifier is invalid")
        if case_id in seen:
            raise ValueError("Authorization case identifiers must be unique")
        title = case["title"]
        if type(title) is not str or not 1 <= len(title.strip()) <= 160:
            raise ValueError("Authorization case title is invalid")
        if not _member(case["grant"], GRANTS) or not _member(case["flow"], FLOWS):
            raise ValueError("Authorization case grant or flow is invalid")
        attempts = case["attempts"]
        if type(attempts) is not list or not 1 <= len(attempts) <= 6:
            raise ValueError("Authorization case requires one to six attempts")
        normalized_attempts = []
        for attempt in attempts:
            _fields(attempt, _ATTEMPT_REQUIRED, _ATTEMPT_OPTIONAL)
            for field, aliases in ARGUMENT_ALIASES.items():
                if field in {"grant", "flow", "fault_mode"} or field == "tenant" and field not in attempt:
                    continue
                if not _member(attempt[field], aliases):
                    raise ValueError("Authorization attempt contains an invalid fixed alias")
            if not _member(attempt["tool"], TOOLS):
                raise ValueError("Authorization attempt tool is invalid")
            peer_action = attempt.get("peer_action", "trusted_forward")
            fault_mode = attempt.get("fault_mode", "none")
            if not _member(peer_action, PEER_ACTIONS) or not _member(fault_mode, FAULT_MODES):
                raise ValueError("Authorization attempt peer action or fault mode is invalid")
            scopes = attempt["scopes"]
            if type(scopes) is not list or len(scopes) != 1 or not _member(scopes[0], SCOPES):
                raise ValueError("Authorization attempt scopes are invalid")
            if type(attempt["depth"]) is not int or not 0 <= attempt["depth"] <= 3:
                raise ValueError("Authorization attempt delegation depth is invalid")
            if type(attempt["tick"]) is not int or not 0 <= attempt["tick"] <= 10:
                raise ValueError("Authorization attempt expiry tick is invalid")
            normalized_attempts.append(
                {**attempt, "scopes": list(scopes), "peer_action": peer_action, "fault_mode": fault_mode}
            )
        for field, allowed in (("expected_decisions", DECISIONS), ("expected_reasons", REASONS)):
            values = case[field]
            if (
                type(values) is not list
                or len(values) != len(attempts)
                or any(not _member(value, allowed) for value in values)
            ):
                raise ValueError("Authorization case expectations are invalid")
        effect_count = case["expected_effect_count"]
        if type(effect_count) is not int or not 0 <= effect_count <= len(attempts):
            raise ValueError("Authorization case effect count is invalid")
        surface = case.get("surface", "local_synthetic_fixture")
        outcome = case.get("expected_outcome", "pass")
        if not _member(surface, SURFACES) or not _member(outcome, OUTCOMES):
            raise ValueError("Authorization case surface or outcome is invalid")
        if surface == "unsupported_provider_surface" and outcome != "unsupported":
            raise ValueError("Unsupported provider cases must expect an unsupported outcome")
        rows.append(
            {
                "schema_version": case["schema_version"],
                "case_id": case_id,
                "title": title,
                "grant": case["grant"],
                "flow": case["flow"],
                "attempts": normalized_attempts,
                "expected_decisions": list(case["expected_decisions"]),
                "expected_reasons": list(case["expected_reasons"]),
                "expected_effect_count": effect_count,
                "surface": surface,
                "expected_outcome": outcome,
            }
        )
        seen.add(case_id)
    if not rows:
        raise ValueError("Authorization laboratory requires at least one case")
    # Clone and reject non-JSON values before data enters the approval contract.
    return tuple(_decode_json(canonical(rows)))


def load_case_inputs(path: str | Path) -> tuple[dict[str, Any], ...]:
    root = Path(path)
    try:
        mode = root.lstat().st_mode
        if stat.S_ISREG(mode):
            paths = [root]
        elif stat.S_ISDIR(mode):
            paths = sorted(root.glob("*.json"))
        else:
            raise JSONInputError("Authorization cases must be regular files or a directory")
        if not 1 <= len(paths) <= 100:
            raise JSONInputError("Authorization laboratory requires one to 100 case files")
        return normalize_case_inputs(
            decode_json(read_regular_file(item, max_bytes=65536), max_bytes=65536) for item in paths
        )
    except OSError as exc:
        raise JSONInputError("Authorization cases could not be read") from exc


def capture_source_bytes(source_root: str | Path) -> dict[str, bytes]:
    return {name: read_regular_file(Path(source_root) / name, max_bytes=1048576) for name in SOURCE_FILES}


def _tool_input_schema() -> dict[str, Any]:
    properties = {
        "grant": {"type": "string", "enum": list(SYNTHETIC_GRANT_ALIASES)},
        "flow": {"type": "string", "enum": list(FLOWS)},
        **{
            field: {"type": "string", "enum": sorted(ARGUMENT_ALIASES[field])}
            for field in ("principal", "agent", "downstream_service", "audience", "tenant", "resource", "operation")
        },
        "scopes": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "uniqueItems": True,
            "items": {"type": "string", "enum": sorted(SCOPES)},
        },
        "depth": {"type": "integer", "minimum": 0, "maximum": 3},
        "tick": {"type": "integer", "minimum": 0, "maximum": 10},
        "case_id": {"type": "string", "pattern": f"^{ID_PATTERN}$", "maxLength": 64},
        **{
            field: {"type": "string", "pattern": f"^{ID_PATTERN}$", "maxLength": 128}
            for field in ("attempt_id", "request_id", "canary_id")
        },
        "plan_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$", "maxLength": 64},
        "test_identity": {"type": "string", "const": TEST_IDENTITY},
        "fault_mode": {"type": "string", "enum": list(FAULT_MODES)},
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(set(properties) - {"tenant"}),
        "properties": properties,
    }


def build_auth_plan(
    cases: Iterable[dict[str, Any]],
    *,
    plan_id: str,
    engagement_id: str,
    created_at: str,
    source_root: str | Path | None = None,
    _sources: dict[str, bytes] | None = None,
) -> ActionPlan:
    rows = normalize_case_inputs(cases)
    if _sources is None:
        if source_root is None:
            raise ValueError("Authorization planning requires an explicit source directory")
        sources = capture_source_bytes(source_root)
    else:
        sources = _sources
    if (
        type(sources) is not dict
        or set(sources) != set(SOURCE_FILES)
        or any(type(raw) is not bytes or len(raw) > 1048576 for raw in sources.values())
    ):
        raise ValueError("Authorization planning requires the complete bounded source snapshot")
    planned_cases = []
    for case in rows:
        attempts = []
        for index, attempt in enumerate(case["attempts"], start=1):
            attempt_id = f"{case['case_id']}-{index}"
            attempts.append(
                {
                    "attempt_id": attempt_id,
                    "request_id": f"request-{attempt_id}",
                    "canary_id": f"canary-{attempt_id}",
                    "request": {"case_id": case["case_id"], "grant": case["grant"], "flow": case["flow"], **attempt},
                    "expectation": {
                        "decision": case["expected_decisions"][index - 1],
                        "reason": case["expected_reasons"][index - 1],
                        "effect_delta": int(case["expected_decisions"][index - 1] == "allowed"),
                    },
                }
            )
        planned_cases.append(
            {
                "schema_version": "cops.agent-mcp-auth-planned-case/v1",
                "surface": case["surface"],
                "case_id": case["case_id"],
                "title": case["title"],
                "attempts": attempts,
                "expected_effect_count": case["expected_effect_count"],
                "expected_outcome": case["expected_outcome"],
            }
        )
    tool_schema = _tool_input_schema()
    manifest = {
        "schema_version": "cops.agent-mcp-auth-manifest/v1",
        "test_identity": TEST_IDENTITY,
        "case_input_sha256": digest(list(rows)),
        "adapter": {
            "adapter_id": ADAPTER_ID,
            "source_sha256": {name: hashlib.sha256(sources[name]).hexdigest() for name in SOURCE_FILES},
            "protocol_version": PROTOCOL_VERSION,
            "server_info": SERVER_INFO,
            "transport": "stdio",
            "tools": list(TOOLS),
            "tool_input_schemas": {tool: tool_schema for tool in TOOLS},
            "tool_permissions": [
                {"tool": "canary/read", "operation": "read", "granted_scopes": ["canary:read"]},
                {"tool": "canary/write", "operation": "write", "granted_scopes": ["canary:write"]},
            ],
            "peer_actions": list(PEER_ACTIONS),
        },
        "cases": planned_cases,
        "fault_modes": {
            "supported": list(FAULT_MODES),
            "hung_server_timeout_seconds": 1,
            "missing_identity_telemetry_outcome": "inconclusive",
            "observer_failure_outcome": "inconclusive",
        },
        "limits": {
            "max_cases": 100,
            "max_attempts_per_case": 6,
            "max_ledger_bytes": 65536,
            "max_response_bytes": 65536,
            "network_egress": False,
        },
        "cleanup": {
            "terminate_fixture_processes": True,
            "verify_process_exit": True,
            "remove_private_work_directory": True,
            "verify_private_directory_removal": True,
        },
    }
    return ActionPlan.create(
        plan_id=plan_id,
        engagement_id=engagement_id,
        created_at=created_at,
        scenario_id=SCENARIO_ID,
        target=TARGET,
        specialist_id=SPECIALIST_ID,
        operations=[
            {
                "step_id": "auth-lab-batch",
                "tool": "foundry-agent-harness/auth-lab",
                "tool_version": "1",
                "action": "run_authorization_batch",
                "arguments": manifest,
                "timeout_seconds": 120,
                "cleanup": manifest["cleanup"],
                "idempotent": False,
                "expected_evidence": [
                    "peer forwarding observation",
                    "target authorization decision",
                    "separate-process canary ledger",
                    "process exit observation",
                    "private directory removal observation",
                ],
                "side_effects": ["private staged source and work directories", "local synthetic canary ledger writes"],
            }
        ],
        limits={"max_duration_seconds": 120, "max_output_bytes": 1048576, "egress_allowed": False},
        credential_references=[],
        platform_prerequisites=["python-standard-library", "local-stdio-processes"],
        batch={"mode": "sequential", "max_operations": 1, "fail_fast": False},
    )
