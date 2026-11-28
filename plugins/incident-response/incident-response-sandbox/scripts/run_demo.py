#!/usr/bin/env python3
"""Run fresh-clock fixture-only incident response playback paths."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from incident_response.core import ActionError, build_plan, dry_run, execute, load_json, save_fixture, validate_plan


class PlaybackError(RuntimeError):
    """Raised when synthetic playback evidence violates its contract."""


def require(condition: bool, message: str) -> None:
    """Fail closed even when Python runs with optimization enabled."""
    if not condition:
        raise PlaybackError(message)


def rejected(callable_: Callable[[], object]) -> dict[str, object]:
    try:
        callable_()
    except ActionError as error:
        return {"rejected": True, "reason": str(error)}
    raise PlaybackError("expected playback rejection")


def main() -> int:
    template = load_json(Path(__file__).resolve().parents[1] / "fixtures" / "synthetic" / "fixture.json")
    now = datetime.now(UTC)
    expires_at = (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(prefix="cops-ir-playback-") as directory:
        staging = Path(directory)
        os.chmod(staging, 0o700)
        fixture_path = staging / "fixture.json"
        fixture_path.write_text(json.dumps(template, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(fixture_path, 0o600)

        plan = build_plan(
            action="isolate-host",
            tenant="example-tenant",
            target="host-1",
            expires_at=expires_at,
            nonce="fresh-clock-primary",
            approver_assertion="synthetic-demo-only",
        )
        fixture = load_json(fixture_path)
        receipt = dry_run(plan, fixture)
        dry_run_state_unchanged = fixture == template
        require(dry_run_state_unchanged, "dry run changed provider state")
        updated, result = execute(plan, receipt, fixture)
        save_fixture(fixture_path, updated)
        persisted = load_json(fixture_path)
        require(persisted == updated, "persisted provider state differs from execution result")

        replay_fixture = deepcopy(template)
        replay_fixture["executions"].append(
            {"plan_hash": plan["plan_hash"], "nonce": plan["nonce"], "outcome": "synthetic-prior-run"}
        )
        replay_rejection = rejected(lambda: execute(plan, receipt, replay_fixture))
        expiry_rejection = rejected(lambda: validate_plan(plan, now=now + timedelta(minutes=11)))

        rollback_fixture = deepcopy(template)
        rollback_fixture["failure_mode"] = "partial"
        rollback_plan = build_plan(
            action="isolate-host",
            tenant="example-tenant",
            target="host-1",
            expires_at=expires_at,
            nonce="fresh-clock-rollback",
            approver_assertion="synthetic-demo-only",
        )
        rollback_receipt = dry_run(rollback_plan, rollback_fixture)
        rolled_back, rollback_result = execute(rollback_plan, rollback_receipt, rollback_fixture)

        output = {
            "schema": "cops.incident-response-playback/v1",
            "execution_boundary": {
                "provider": "local JSON fixture",
                "network_calls": 0,
                "live_containment_validated": False,
                "temporary_artifacts_removed": False,
            },
            "primary": {
                "plan_hash": plan["plan_hash"],
                "dry_run_decision": receipt["decision"],
                "dry_run_state_unchanged": dry_run_state_unchanged,
                "execute_status": result["outcome"],
                "provider_request_id": result["provider_request_id"],
                "verification_state": persisted["targets"]["host-1"]["state"],
                "post_action_verification": result["post_action_verification"],
            },
            "replay_rejection": replay_rejection,
            "expiry_rejection": expiry_rejection,
            "rollback": {
                "execute_status": rollback_result["outcome"],
                "verification_state": rolled_back["targets"]["host-1"]["state"],
                "post_action_verification": rollback_result["post_action_verification"],
            },
        }
    removed = not staging.exists()
    output["execution_boundary"]["temporary_artifacts_removed"] = removed
    require(output["primary"]["dry_run_decision"] == "ready", "dry-run receipt is not ready")
    require(output["primary"]["dry_run_state_unchanged"] is True, "dry-run mutation evidence is invalid")
    require(output["primary"]["verification_state"] == "isolated", "execution did not isolate the target")
    require(output["replay_rejection"]["rejected"] is True, "replay was not rejected")
    require(output["expiry_rejection"]["rejected"] is True, "expired plan was not rejected")
    require(output["rollback"]["execute_status"] == "partial-rolled-back", "partial failure did not roll back")
    require(output["rollback"]["verification_state"] == "active", "rollback did not restore target state")
    require(removed, "temporary playback directory was not removed")
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
