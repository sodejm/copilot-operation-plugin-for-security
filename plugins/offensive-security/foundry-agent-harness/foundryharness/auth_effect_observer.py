"""Separate fixed-process witness for synthetic MCP canary operations.

This observes effects inside the local fixture. It is not an external service
attestation or an operating-system boundary against a malicious local process.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

OBSERVER_IDENTITY = "fixed-effect-observer"
TARGET_IDENTITY = "fixed-target-authorization-service"
TEST_IDENTITY = "synthetic-fixture-runner"
REQUEST_FIELDS = frozenset(
    {
        "command",
        "case_id",
        "attempt_id",
        "request_id",
        "canary_id",
        "plan_digest",
        "test_identity",
        "principal",
        "tool",
        "tenant",
        "resource",
        "operation",
        "fault_mode",
    }
)
ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


def _valid(request: Any) -> bool:
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS or request["command"] != "effect":
        return False
    if request["test_identity"] != TEST_IDENTITY or request["resource"] != "res-canary":
        return False
    if request["tenant"] not in {"tenant-contoso-01", "tenant-fabrikam-02"}:
        return False
    if request["principal"] not in {"principal-alice", "principal-bob", "service-scheduler"}:
        return False
    if request["operation"] not in {"read", "write"} or request["tool"] != f"canary/{request['operation']}":
        return False
    if request["fault_mode"] not in {"none", "observer_failure", "lost_response_after_effect"}:
        return False
    if any(
        not isinstance(request[key], str) or len(request[key]) > limit or ID_PATTERN.fullmatch(request[key]) is None
        for key, limit in (("case_id", 64), ("attempt_id", 128), ("request_id", 128), ("canary_id", 128))
    ):
        return False
    return isinstance(request["plan_digest"], str) and re.fullmatch(r"[0-9a-f]{64}", request["plan_digest"]) is not None


def _append_event(event: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    descriptor = os.open("effects.jsonl", flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
            raise ValueError("Effect observer ledger unavailable")
        raw = (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > 4096 or metadata.st_size + len(raw) > 65536:
            raise ValueError("Effect observer ledger limit exceeded")
        if os.write(descriptor, raw) != len(raw):
            raise ValueError("Effect observer ledger write incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _effect(request: Any, canaries: dict[str, str]) -> dict[str, Any]:
    if not _valid(request):
        return {"recorded": False}
    operation = request["operation"]
    tenant = request["tenant"]
    if operation == "write":
        canaries[tenant] = "synthetic-canary"
    elif tenant not in canaries:
        return {"recorded": False}
    event = {
        "schema_version": "cops.agent-mcp-auth-ledger-event/v1",
        **{
            key: request[key]
            for key in (
                "case_id",
                "attempt_id",
                "request_id",
                "canary_id",
                "plan_digest",
                "test_identity",
                "principal",
                "tool",
                "tenant",
                "resource",
                "operation",
            )
        },
        "server_identity": TARGET_IDENTITY,
        "kind": f"canary_{operation}",
        "redacted": True,
    }
    _append_event({"observer_fault": True} if request["fault_mode"] == "observer_failure" else event)
    response: dict[str, Any] = {"recorded": True}
    if operation == "read":
        response["canary"] = canaries[tenant]
    return response


def main() -> int:
    ready = json.loads(sys.stdin.readline())
    if ready != {"command": "ready"}:
        return 2
    canaries = {"tenant-contoso-01": "synthetic-canary", "tenant-fabrikam-02": "synthetic-canary"}
    sys.stdout.write(json.dumps({"ready": True, "observer_identity": OBSERVER_IDENTITY}) + "\n")
    sys.stdout.flush()
    while True:
        requests = sorted(Path.cwd().glob("observer-*.request"))
        if not requests:
            time.sleep(0.005)
            continue
        for request_path in requests:
            attempt_id = request_path.name.removeprefix("observer-").removesuffix(".request")
            if re.fullmatch(ID_PATTERN, attempt_id) is None or len(attempt_id) > 128:
                continue
            try:
                descriptor = os.open(request_path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size >= 8192:
                        raise ValueError("Invalid effect observer request file")
                    raw = os.read(descriptor, 8192)
                finally:
                    os.close(descriptor)
                if not raw.endswith(b"\n") or len(raw) >= 8192:
                    raise ValueError("Invalid effect observer request")
                request = json.loads(raw)
                if not isinstance(request, dict) or request.get("attempt_id") != attempt_id:
                    raise ValueError("Effect observer request identity mismatch")
                response = _effect(request, canaries)
            except (ValueError, TypeError, OSError, json.JSONDecodeError):
                response = {"recorded": False}
            request_path.unlink(missing_ok=True)
            temporary_path = Path(f".observer-{attempt_id}.response.tmp")
            response_path = Path(f"observer-{attempt_id}.response")
            raw_response = (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
            descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                if os.write(descriptor, raw_response) != len(raw_response):
                    raise ValueError("Effect observer response write incomplete")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary_path, response_path)


if __name__ == "__main__":
    raise SystemExit(main())
