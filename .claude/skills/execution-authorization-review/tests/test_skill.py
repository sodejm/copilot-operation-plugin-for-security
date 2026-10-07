"""Tests for execution-authorization-review contributor skill."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cops.contracts.models import ActionPlan
from cops.execution import (
    consume_execution_authorization,
    verify_execution_authorization,
)
from tests.auth_testkit import authorize_test_plan


class TestExecutionAuthorizationReviewSkill(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parents[4] / "cops" / "contracts" / "fixtures"
        plan_doc = json.loads((self.fixtures_dir / "valid_action_plan.json").read_text(encoding="utf-8"))
        self.plan = ActionPlan.from_dict(plan_doc)

    def test_end_to_end_skill_flow(self):
        # 1. Create authorization envelope
        auth, trust_store, engagement = authorize_test_plan(
            self.plan,
            valid_hours=2,
            worker_identity="worker-node-1",
        )
        self.assertEqual(auth.status, "approved")
        self.assertEqual(auth.schema_version, "cops.execution-authorization/v1")

        # 2. Verify authorization against plan
        verified = verify_execution_authorization(
            auth,
            self.plan,
            trust_store=trust_store,
            engagement=engagement,
            worker_identity="worker-node-1",
        )
        self.assertEqual(verified.authorization_id, auth.authorization_id)

        # 3. Consume authorization
        consumed = consume_execution_authorization(
            verified,
            worker_identity="worker-node-1",
        )
        self.assertEqual(consumed.status, "consumed")
        self.assertEqual(consumed.consumed_by_worker, "worker-node-1")


if __name__ == "__main__":
    unittest.main()
