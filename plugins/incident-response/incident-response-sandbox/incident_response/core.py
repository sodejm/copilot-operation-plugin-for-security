"""Typed, fail-closed incident actions against a synthetic JSON fixture."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypedDict

Action = Literal["isolate-host", "revoke-session"]
PLAN_FIELDS = {
    "schema",
    "action",
    "tenant",
    "target",
    "parameters",
    "expected_state",
    "desired_state",
    "expires_at",
    "nonce",
    "approver_assertion",
    "plan_hash",
}
RECEIPT_FIELDS = {"schema", "plan_hash", "fixture_revision", "target_state_hash", "decision"}


class Plan(TypedDict):
    schema: str
    action: Action
    tenant: str
    target: str
    parameters: dict[str, str]
    expected_state: str
    desired_state: str
    expires_at: str
    nonce: str
    approver_assertion: str
    plan_hash: str


class ActionError(ValueError):
    """Stable rejection for invalid or unsafe action input."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or not all(char.isascii() and (char.isalnum() or char in "-_.@") for char in value)
    ):
        raise ActionError(f"invalid {label}")
    return value


def _expiry(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ActionError("invalid expiry")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ActionError("invalid expiry") from error
    if parsed.tzinfo is None:
        raise ActionError("expiry must include a timezone")
    return parsed.astimezone(UTC)


def validate_plan(plan: object, *, now: datetime | None = None) -> Plan:
    if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS or plan["schema"] != "cops.ir-plan/v1":
        raise ActionError("invalid plan schema")
    for key in ("tenant", "target", "nonce", "approver_assertion"):
        _identifier(plan[key], key)
    action = plan["action"]
    states = {"isolate-host": ("active", "isolated"), "revoke-session": ("valid", "revoked")}
    if (
        not isinstance(action, str)
        or action not in states
        or (plan["expected_state"], plan["desired_state"]) != states[action]
    ):
        raise ActionError("unsupported action or state transition")
    if not isinstance(plan["parameters"], dict) or plan["parameters"]:
        raise ActionError("parameters must be an empty object for fixture actions")
    expiry = _expiry(plan["expires_at"])
    if expiry <= (now or datetime.now(UTC)):
        raise ActionError("plan expired")
    supplied = plan["plan_hash"]
    if not isinstance(supplied, str) or supplied != _digest({k: v for k, v in plan.items() if k != "plan_hash"}):
        raise ActionError("plan hash mismatch")
    return plan  # type: ignore[return-value]


def build_plan(
    *, action: Action, tenant: str, target: str, expires_at: str, nonce: str, approver_assertion: str
) -> Plan:
    states = {"isolate-host": ("active", "isolated"), "revoke-session": ("valid", "revoked")}
    if not isinstance(action, str) or action not in states:
        raise ActionError("unsupported action")
    expected, desired = states[action]
    plan = {
        "schema": "cops.ir-plan/v1",
        "action": action,
        "tenant": tenant,
        "target": target,
        "parameters": {},
        "expected_state": expected,
        "desired_state": desired,
        "expires_at": expires_at,
        "nonce": nonce,
        "approver_assertion": approver_assertion,
    }
    plan["plan_hash"] = _digest(plan)
    return validate_plan(plan)


def _fixture(fixture: object) -> dict:
    if not isinstance(fixture, dict) or fixture.get("schema") != "cops.ir-fixture/v1":
        raise ActionError("invalid fixture schema")
    if not isinstance(fixture.get("revision"), int) or fixture["revision"] < 0:
        raise ActionError("invalid fixture revision")
    if not isinstance(fixture.get("targets"), dict) or not isinstance(fixture.get("executions"), list):
        raise ActionError("invalid fixture records")
    if not isinstance(fixture.get("permissions"), list):
        raise ActionError("invalid fixture permissions")
    if "verification_available" in fixture and not isinstance(fixture["verification_available"], bool):
        raise ActionError("invalid verification availability")
    return fixture


def _check(plan: Plan, fixture: dict) -> str:
    if fixture.get("tenant") != plan["tenant"]:
        raise ActionError("tenant mismatch")
    target = fixture["targets"].get(plan["target"])
    if not isinstance(target, dict) or target.get("action") != plan["action"]:
        raise ActionError("target mismatch")
    if target.get("state") != plan["expected_state"]:
        raise ActionError("expected state drift")
    if plan["action"] not in fixture["permissions"]:
        raise ActionError("permission denied")
    if fixture.get("throttled") is True:
        raise ActionError("throttled")
    if any(
        record.get("plan_hash") == plan["plan_hash"] or record.get("nonce") == plan["nonce"]
        for record in fixture["executions"]
        if isinstance(record, dict)
    ):
        raise ActionError("duplicate or replayed plan")
    return _digest(target)


def dry_run(plan: object, fixture: object) -> dict:
    checked = validate_plan(plan)
    state = _fixture(fixture)
    state_hash = _check(checked, state)
    return {
        "schema": "cops.ir-dry-run/v1",
        "plan_hash": checked["plan_hash"],
        "fixture_revision": state["revision"],
        "target_state_hash": state_hash,
        "decision": "ready",
    }


def _verification(state: dict, target: dict, desired_state: str) -> dict:
    if state.get("verification_available", True) is False:
        return {"reference": None, "result": "unavailable"}
    return {
        "reference": f"fixture-state-sha256-{_digest(target)}",
        "result": "succeeded" if target.get("state") == desired_state else "failed",
    }


def execute(plan: object, receipt: object, fixture: object) -> tuple[dict, dict]:
    checked = validate_plan(plan)
    state = _fixture(fixture)
    if (
        not isinstance(receipt, dict)
        or set(receipt) != RECEIPT_FIELDS
        or receipt["schema"] != "cops.ir-dry-run/v1"
        or receipt["decision"] != "ready"
    ):
        raise ActionError("explicit dry run receipt required")
    if receipt["plan_hash"] != checked["plan_hash"] or receipt["fixture_revision"] != state["revision"]:
        raise ActionError("dry run receipt drift")
    state_hash = _check(checked, state)
    if receipt["target_state_hash"] != state_hash:
        raise ActionError("target changed after dry run")
    mode = state.get("failure_mode", "none")
    if mode not in ("none", "partial", "rollback-failed"):
        raise ActionError("invalid fixture failure mode")
    target = state["targets"][checked["target"]]
    previous = target["state"]
    target["state"] = checked["desired_state"]
    if mode == "partial":
        target["state"] = previous
        outcome = "partial-rolled-back"
    elif mode == "rollback-failed":
        outcome = "partial-rollback-failed"
    else:
        outcome = "applied"
    state["revision"] += 1
    provider_request_id = f"fixture-request-{checked['plan_hash']}"
    verification = _verification(state, target, checked["desired_state"])
    state["executions"].append(
        {
            "plan_hash": checked["plan_hash"],
            "nonce": checked["nonce"],
            "outcome": outcome,
            "provider_request_id": provider_request_id,
            "post_action_verification": dict(verification),
        }
    )
    return state, {
        "schema": "cops.ir-result/v1",
        "plan_hash": checked["plan_hash"],
        "outcome": outcome,
        "fixture_revision": state["revision"],
        "approval_provenance": "unverified-operator-assertion",
        "provider_request_id": provider_request_id,
        "post_action_verification": verification,
    }


def load_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ActionError("unsafe or oversized local input")
    return json.loads(path.read_text(encoding="utf-8"))


def save_fixture(path: Path, fixture: dict) -> None:
    """Replace only the operator-selected fixture in a private staging directory."""
    if path.is_symlink() or not path.is_file() or path.parent.stat().st_mode & 0o077 or path.stat().st_mode & 0o077:
        raise ActionError("fixture requires a private, regular-file staging path")
    descriptor, staged = tempfile.mkstemp(prefix=".ir-fixture-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(fixture, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staged, 0o600)
        os.replace(staged, path)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)
