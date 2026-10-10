"""Behavior and abuse cases for the fixture-only action contract."""

from __future__ import annotations

import re
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from incident_response.core import ActionError, build_plan, dry_run, execute


def fixture() -> dict:
    return {"schema": "cops.ir-fixture/v1", "tenant": "example-tenant", "revision": 1,
            "permissions": ["isolate-host"], "throttled": False, "failure_mode": "none",
            "targets": {"host-1": {"action": "isolate-host", "state": "active"},
                        "host-2": {"action": "isolate-host", "state": "active"}},
            "executions": []}


def plan() -> dict:
    return build_plan(action="isolate-host", tenant="example-tenant", target="host-1",
                      expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                      nonce="unique-1", approver_assertion="analyst-1")


class SandboxTests(unittest.TestCase):
    def test_explicit_dry_run_only_named_target_and_replay(self):
        p, f = plan(), fixture()
        with self.assertRaisesRegex(ActionError, "dry run"):
            execute(p, {}, f)
        receipt = dry_run(p, f)
        updated, result = execute(p, receipt, f)
        self.assertEqual(result["outcome"], "applied")
        self.assertRegex(result["provider_request_id"], r"^fixture-request-[0-9a-f]{64}$")
        self.assertEqual(result["post_action_verification"]["result"], "succeeded")
        self.assertRegex(
            result["post_action_verification"]["reference"],
            r"^fixture-state-sha256-[0-9a-f]{64}$",
        )
        self.assertEqual(updated["targets"]["host-1"]["state"], "isolated")
        self.assertEqual(updated["targets"]["host-2"]["state"], "active")
        with self.assertRaises(ActionError):
            execute(p, receipt, updated)

    def test_plan_tampering_and_expiry(self):
        p = plan()
        p["target"] = "host-2"
        with self.assertRaisesRegex(ActionError, "hash"):
            dry_run(p, fixture())
        with self.assertRaisesRegex(ActionError, "expired"):
            build_plan(action="isolate-host", tenant="example-tenant", target="host-1",
                       expires_at="2000-01-01T00:00:00Z", nonce="old", approver_assertion="analyst")

    def test_drift_permission_throttle(self):
        p, f = plan(), fixture()
        receipt = dry_run(p, f)
        f["targets"]["host-1"]["state"] = "isolated"
        with self.assertRaisesRegex(ActionError, "drift"):
            execute(p, receipt, f)
        f = fixture()
        f["permissions"] = []
        with self.assertRaisesRegex(ActionError, "permission"):
            dry_run(p, f)
        f = fixture()
        f["throttled"] = True
        with self.assertRaisesRegex(ActionError, "throttled"):
            dry_run(p, f)

    def test_partial_and_failed_rollback_are_distinct(self):
        for mode, expected, state in (("partial", "partial-rolled-back", "active"),
                                      ("rollback-failed", "partial-rollback-failed", "isolated")):
            with self.subTest(mode=mode):
                f = fixture()
                f["failure_mode"] = mode
                p = plan()
                updated, result = execute(p, dry_run(p, f), f)
                self.assertEqual(result["outcome"], expected)
                self.assertEqual(updated["targets"]["host-1"]["state"], state)
                self.assertEqual(len(updated["executions"]), 1)
                expected_verification = "failed" if mode == "partial" else "succeeded"
                self.assertEqual(
                    result["post_action_verification"]["result"], expected_verification
                )

    def test_unavailable_verification_is_explicit(self):
        p, f = plan(), fixture()
        f["verification_available"] = False
        updated, result = execute(p, dry_run(p, f), f)
        self.assertEqual(result["outcome"], "applied")
        self.assertEqual(
            result["post_action_verification"],
            {"reference": None, "result": "unavailable"},
        )
        self.assertEqual(
            updated["executions"][0]["post_action_verification"],
            result["post_action_verification"],
        )

    def test_receipt_evidence_uses_secret_free_generated_identifiers(self):
        p, f = plan(), fixture()
        updated, result = execute(p, dry_run(p, f), f)
        evidence = result["post_action_verification"]
        self.assertTrue(re.fullmatch(r"[a-z0-9-]+", result["provider_request_id"]))
        self.assertTrue(re.fullmatch(r"[a-z0-9-]+", evidence["reference"]))
        self.assertNotIn("example-tenant", str(result))
        self.assertEqual(
            updated["executions"][0]["provider_request_id"],
            result["provider_request_id"],
        )

    def test_duplicate_nonce(self):
        p, f = plan(), fixture()
        f["executions"].append({"plan_hash": "different", "nonce": p["nonce"]})
        with self.assertRaisesRegex(ActionError, "replayed"):
            dry_run(p, f)

    def test_invalid_action_and_failure_mode_do_not_mutate(self):
        p, f = plan(), fixture()
        p["action"] = []
        with self.assertRaises(ActionError):
            dry_run(p, f)
        p = plan()
        receipt = dry_run(p, f)
        f["failure_mode"] = "unknown"
        with self.assertRaisesRegex(ActionError, "failure mode"):
            execute(p, receipt, f)
        self.assertEqual(f["targets"]["host-1"]["state"], "active")
        self.assertEqual(f["revision"], 1)

        f = fixture()
        f["verification_available"] = "sometimes"
        with self.assertRaisesRegex(ActionError, "verification availability"):
            execute(p, dry_run(p, fixture()), f)
        self.assertEqual(f["targets"]["host-1"]["state"], "active")


if __name__ == "__main__":
    unittest.main()
