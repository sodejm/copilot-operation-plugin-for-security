"""Fixed MCP stdio server for synthetic delegation authorization cases.

Grant aliases are local test data, not bearer credentials. The only persistent
side effect is an append to the runner-created canary ledger in the workdir.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-11-25"
SERVER_INFO = {"name": "cops-auth-fixture", "version": "1"}
TOOLS = ("canary/read", "canary/write")
FLOWS = ("delegated", "autonomous")
FAULT_MODES = ("none", "hung_server", "missing_identity_telemetry", "observer_failure")
PEER_ACTIONS = ("trusted_forward", "mutate_tenant", "omit_tenant", "mutate_operation", "substitute_receipt")
TEST_IDENTITY = "synthetic-fixture-runner"
SERVER_IDENTITY = "fixed-target-authorization-service"
GRANTS = {
    "delegated-write": {
        "principal": "principal-alice",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/write",
        "scope": "canary:write",
        "tenant": "tenant-contoso-01",
        "expires_at": 10,
    },
    "delegated-write-fabrikam": {
        "principal": "principal-bob",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/write",
        "scope": "canary:write",
        "tenant": "tenant-fabrikam-02",
        "expires_at": 10,
    },
    "autonomous-write": {
        "principal": "service-scheduler",
        "agent": "agent-worker",
        "mode": "autonomous",
        "tool": "canary/write",
        "scope": "canary:write",
        "tenant": "tenant-contoso-01",
        "expires_at": 10,
    },
    "one-time-write": {
        "principal": "principal-alice",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/write",
        "scope": "canary:write",
        "tenant": "tenant-contoso-01",
        "expires_at": 10,
        "one_time": True,
    },
    "reusable-write": {
        "principal": "principal-alice",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/write",
        "scope": "canary:write",
        "tenant": "tenant-contoso-01",
        "expires_at": 10,
    },
    "expired-write": {
        "principal": "principal-alice",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/write",
        "scope": "canary:write",
        "tenant": "tenant-contoso-01",
        "expires_at": 3,
    },
    "revoked-write": {
        "principal": "principal-alice",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/write",
        "scope": "canary:write",
        "tenant": "tenant-contoso-01",
        "expires_at": 10,
        "revoked_at": 3,
    },
    "read-only": {
        "principal": "principal-alice",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/read",
        "scope": "canary:read",
        "tenant": "tenant-contoso-01",
        "expires_at": 10,
    },
    "read-only-fabrikam": {
        "principal": "principal-bob",
        "agent": "agent-worker",
        "mode": "delegated",
        "tool": "canary/read",
        "scope": "canary:read",
        "tenant": "tenant-fabrikam-02",
        "expires_at": 10,
    },
}
SYNTHETIC_GRANT_ALIASES = (*GRANTS, "receipt-approved-synthetic")
ARGUMENT_FIELDS = frozenset({
    "grant",
    "flow",
    "principal",
    "agent",
    "downstream_service",
    "audience",
    "tenant",
    "resource",
    "operation",
    "scopes",
    "depth",
    "tick",
    "attempt_id",
    "request_id",
    "canary_id",
    "plan_digest",
    "test_identity",
    "fault_mode",
})
REQUIRED_ARGUMENT_FIELDS = ARGUMENT_FIELDS - {"tenant"}
ARGUMENT_ALIASES = {
    "grant": set(SYNTHETIC_GRANT_ALIASES),
    "flow": set(FLOWS),
    "principal": {"principal-alice", "principal-bob", "service-scheduler"},
    "agent": {"agent-worker", "agent-shadow"},
    "downstream_service": {"service-canary", "service-shadow"},
    "audience": {"mcp://auth-fixture", "mcp://shadow"},
    "tenant": {"tenant-contoso-01", "tenant-fabrikam-02"},
    "resource": {"res-canary", "res-other"},
    "operation": {"read", "write"},
    "fault_mode": set(FAULT_MODES),
}
SCOPES = {"canary:read", "canary:write", "canary:admin"}
ID_PATTERN = r"[a-z0-9]+(?:-[a-z0-9]+)*"
TOOL_INPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": sorted(REQUIRED_ARGUMENT_FIELDS),
    "properties": {
        "grant": {"type": "string", "enum": list(SYNTHETIC_GRANT_ALIASES)},
        "flow": {"type": "string", "enum": list(FLOWS)},
        "principal": {"type": "string", "enum": sorted(ARGUMENT_ALIASES["principal"])},
        "agent": {"type": "string", "enum": sorted(ARGUMENT_ALIASES["agent"])},
        "downstream_service": {"type": "string", "enum": sorted(ARGUMENT_ALIASES["downstream_service"])},
        "audience": {"type": "string", "enum": sorted(ARGUMENT_ALIASES["audience"])},
        "tenant": {"type": "string", "enum": sorted(ARGUMENT_ALIASES["tenant"])},
        "resource": {"type": "string", "enum": sorted(ARGUMENT_ALIASES["resource"])},
        "operation": {"type": "string", "enum": sorted(ARGUMENT_ALIASES["operation"])},
        "scopes": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "uniqueItems": True,
            "items": {"type": "string", "enum": sorted(SCOPES)},
        },
        "depth": {"type": "integer", "minimum": 0, "maximum": 3},
        "tick": {"type": "integer", "minimum": 0, "maximum": 10},
        "attempt_id": {"type": "string", "pattern": ID_PATTERN},
        "request_id": {"type": "string", "pattern": ID_PATTERN},
        "canary_id": {"type": "string", "pattern": ID_PATTERN},
        "plan_digest": {"type": "string", "pattern": r"[0-9a-f]{64}"},
        "test_identity": {"type": "string", "const": TEST_IDENTITY},
        "fault_mode": {"type": "string", "enum": list(FAULT_MODES)},
    },
}
TOOL_INPUT_SCHEMAS = {name: TOOL_INPUT_SCHEMA for name in TOOLS}
TOOL_PERMISSIONS = (
    {"tool": "canary/read", "operation": "read", "granted_scopes": ["canary:read"]},
    {"tool": "canary/write", "operation": "write", "granted_scopes": ["canary:write"]},
)


def _correlation(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "attempt_id": args["attempt_id"],
        "request_id": args["request_id"],
        "canary_id": args["canary_id"],
        "plan_digest": args["plan_digest"],
        "test_identity": args["test_identity"],
    }


def _result(
    args: dict[str, Any],
    decision: str,
    phase: str,
    reason: str,
) -> dict[str, Any]:
    value = {
        "schema_version": "cops.agent-mcp-auth-decision/v1",
        **_correlation(args),
        "target_grant_alias": args["grant"],
        "decision": decision,
        "phase": phase,
        "reason": reason,
        "redacted": True,
    }
    if args["fault_mode"] != "missing_identity_telemetry":
        value["server_identity"] = SERVER_IDENTITY
    return value


def _valid_arguments(args: dict[str, Any]) -> bool:
    if set(args) not in (REQUIRED_ARGUMENT_FIELDS, ARGUMENT_FIELDS):
        return False
    for key, allowed in ARGUMENT_ALIASES.items():
        if key == "tenant" and key not in args:
            continue
        if not isinstance(args.get(key), str) or args[key] not in allowed:
            return False
    return (
        isinstance(args["scopes"], list)
        and len(args["scopes"]) == 1
        and isinstance(args["scopes"][0], str)
        and args["scopes"][0] in SCOPES
        and type(args["depth"]) is int
        and 0 <= args["depth"] <= 3
        and type(args["tick"]) is int
        and 0 <= args["tick"] <= 10
        and all(
            isinstance(args[key], str) and 1 <= len(args[key]) <= 128
            for key in ("attempt_id", "request_id", "canary_id")
        )
        and isinstance(args["plan_digest"], str)
        and len(args["plan_digest"]) == 64
        and all(character in "0123456789abcdef" for character in args["plan_digest"])
        and args["test_identity"] == TEST_IDENTITY
    )


def _decision(name: str, args: dict[str, Any], used: set[str]) -> dict[str, Any]:
    """Separate grant/actor authentication from target authorization."""
    if not _valid_arguments(args):
        raise ValueError("Malformed fixed authorization request")
    if "tenant" not in args:
        return _result(args, "denied", "authorization", "missing_tenant")
    grant = GRANTS.get(args["grant"])
    if grant is None or args["agent"] not in {"agent-worker", "agent-shadow"}:
        return _result(args, "denied", "authentication", "unrecognized_grant_or_actor")
    if args["tick"] >= grant["expires_at"]:
        return _result(args, "denied", "authentication", "expired_grant")
    if args["tick"] >= grant.get("revoked_at", 10):
        return _result(args, "denied", "authentication", "revoked_grant")
    if grant.get("one_time") and args["grant"] in used:
        return _result(args, "denied", "authentication", "one_time_replay")
    checks = (
        (args["flow"] == grant["mode"], "flow_mismatch"),
        (args["principal"] == grant["principal"] and args["agent"] == grant["agent"], "principal_or_agent_binding"),
        (args["downstream_service"] == "service-canary", "downstream_service_mismatch"),
        (args["audience"] == "mcp://auth-fixture", "audience_mismatch"),
        (args["tenant"] == grant["tenant"], "tenant_mismatch"),
        (args["resource"] == "res-canary", "resource_mismatch"),
        (args["depth"] <= 1, "delegation_depth_exceeded"),
        (name == grant["tool"], "tool_not_permitted"),
        (args["operation"] == ("write" if name == "canary/write" else "read"), "operation_mismatch"),
        (args["scopes"] == [grant["scope"]], "scope_mismatch"),
    )
    for valid, reason in checks:
        if not valid:
            return _result(args, "denied", "authorization", reason)
    used.add(args["grant"])
    return _result(args, "allowed", "authorization", "allowed")


def _append_effect(args: dict[str, Any]) -> None:
    ledger = Path.cwd() / "effects.jsonl"
    if ledger.is_symlink() or not ledger.is_file():
        raise ValueError("Side-effect ledger unavailable")
    event: dict[str, Any] = {
        "schema_version": "cops.agent-mcp-auth-ledger-event/v1",
        **_correlation(args),
        "server_identity": SERVER_IDENTITY,
        "kind": "canary_write",
        "tenant": args["tenant"],
        "resource": args["resource"],
        "operation": "write",
        "redacted": True,
    }
    if args["fault_mode"] == "observer_failure":
        event = {"observer_fault": True}
    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(ledger, flags)
    try:
        os.write(fd, (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _tool_result(value: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}], "isError": False}


def main() -> int:
    initialized = False
    used: set[str] = set()
    for line in sys.stdin:
        request: Any = None
        try:
            request = json.loads(line)
            method = request["method"]
            request_id = request.get("id")
            if method == "initialize":
                if request["params"]["protocolVersion"] != PROTOCOL_VERSION:
                    raise ValueError("Unsupported protocol version")
                result = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}
            elif method == "notifications/initialized":
                initialized = True
                continue
            elif not initialized:
                raise ValueError("MCP client has not completed initialization")
            elif method == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": name,
                            "description": "Synthetic local canary operation",
                            "inputSchema": TOOL_INPUT_SCHEMAS[name],
                        }
                        for name in TOOLS
                    ]
                }
            elif method == "tools/call":
                params = request["params"]
                name = params["name"]
                args = params["arguments"]
                if name not in TOOLS or not isinstance(args, dict):
                    raise ValueError("Unsupported synthetic tool")
                if args.get("fault_mode") == "hung_server":
                    threading.Event().wait()
                decision = _decision(name, args, used)
                if decision["decision"] == "allowed" and name == "canary/write":
                    _append_effect(args)
                result = _tool_result(decision)
            else:
                raise ValueError("Unknown MCP method")
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as exc:
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id") if isinstance(request, dict) else None,
                "error": {"code": -32602, "message": f"Invalid fixed fixture request ({type(exc).__name__})"},
            }
        if response["id"] is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
