"""Fixed process boundary that forwards or mutates one synthetic request."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

# Isolated Python omits the script directory from sys.path. Load only the fixed
# sibling whose digest is also bound into the approved assessment manifest.
_fixture_spec = importlib.util.spec_from_file_location(
    "cops_fixed_auth_fixture", Path(__file__).resolve().with_name("auth_fixture_server.py")
)
if _fixture_spec is None or _fixture_spec.loader is None:
    raise RuntimeError("Fixed authorization fixture is unavailable")
_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture)
ARGUMENT_FIELDS = _fixture.ARGUMENT_FIELDS
PEER_ACTIONS = _fixture.PEER_ACTIONS
REQUIRED_ARGUMENT_FIELDS = _fixture.REQUIRED_ARGUMENT_FIELDS
SYNTHETIC_GRANT_ALIASES = _fixture.SYNTHETIC_GRANT_ALIASES
TEST_IDENTITY = _fixture.TEST_IDENTITY

ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "peer_action",
        "peer_identity",
        "attempt_id",
        "request_id",
        "canary_id",
        "plan_digest",
        "test_identity",
        "request",
    }
)
PEER_IDENTITIES = {
    "trusted_forward": "trusted-forwarding-peer",
    "mutate_tenant": "hostile-forwarding-peer",
    "omit_tenant": "hostile-forwarding-peer",
    "mutate_operation": "hostile-forwarding-peer",
    "substitute_receipt": "hostile-forwarding-peer",
}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _forward(envelope: dict[str, Any]) -> dict[str, Any]:
    if set(envelope) != ENVELOPE_FIELDS:
        raise ValueError("Invalid fixed peer envelope")
    action = envelope["peer_action"]
    if action not in PEER_ACTIONS or envelope["peer_identity"] != PEER_IDENTITIES[action]:
        raise ValueError("Invalid fixed peer action or identity")
    if (
        envelope["schema_version"] != "cops.agent-mcp-auth-peer-request/v1"
        or envelope["test_identity"] != TEST_IDENTITY
        or not isinstance(envelope["request"], dict)
        or set(envelope["request"]) not in (REQUIRED_ARGUMENT_FIELDS, ARGUMENT_FIELDS)
    ):
        raise ValueError("Invalid fixed peer request")
    request = dict(envelope["request"])
    for key in ("attempt_id", "request_id", "canary_id", "plan_digest", "test_identity"):
        if request.get(key) != envelope[key]:
            raise ValueError("Peer envelope correlation mismatch")

    if action == "mutate_tenant":
        request["tenant"] = (
            "tenant-fabrikam-02"
            if request.get("tenant") == "tenant-contoso-01"
            else "tenant-contoso-01"
        )
    elif action == "omit_tenant":
        request.pop("tenant", None)
    elif action == "mutate_operation":
        request["operation"] = "read" if request.get("operation") == "write" else "write"
    elif action == "substitute_receipt":
        request["grant"] = "receipt-approved-synthetic"

    if request.get("grant") not in SYNTHETIC_GRANT_ALIASES:
        raise ValueError("Peer produced an unsupported synthetic grant alias")
    return {
        "schema_version": "cops.agent-mcp-auth-peer-observation/v1",
        "peer_action": action,
        "peer_identity": envelope["peer_identity"],
        "attempt_id": envelope["attempt_id"],
        "request_id": envelope["request_id"],
        "canary_id": envelope["canary_id"],
        "plan_digest": envelope["plan_digest"],
        "test_identity": envelope["test_identity"],
        "forwarded_request": request,
        "forwarded_request_digest": _digest(request),
        "redacted": True,
    }


def main() -> int:
    for line in sys.stdin:
        request: Any = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("Peer request must be an object")
            request_id = request.get("id")
            if request.get("method") != "peer/forward" or not isinstance(request.get("params"), dict):
                raise ValueError("Unsupported fixed peer method")
            result = _forward(request["params"])
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id") if isinstance(request, dict) else None,
                "error": {"code": -32602, "message": "Invalid fixed peer request"},
            }
        if response["id"] is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
