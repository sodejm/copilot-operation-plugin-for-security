"""Tests for worker-readiness-and-approval contributor skill."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cops.contracts.models import ActionPlan
from cops.execution import ApprovalStore, IsolatedWorker
from tests.auth_testkit import (
    TestApprovalControl,
    TestExecutionSandbox,
    authorize_test_plan,
    worker_inventory_for_plan,
)


class TestWorkerReadinessAndApprovalSkill(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_approvals.sqlite3"
        self.store = ApprovalStore(self.db_path)
        self.fixtures_dir = Path(__file__).resolve().parents[4] / "cops" / "contracts" / "fixtures"
        plan_doc = json.loads((self.fixtures_dir / "valid_action_plan.json").read_text(encoding="utf-8"))
        self.plan = ActionPlan.from_dict(plan_doc)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_worker_and_approval_skill_flow(self):
        # 1. Create and store authorization
        auth, trust_store, engagement = authorize_test_plan(
            self.plan,
            valid_hours=2,
            worker_identity="worker-test-01",
        )
        self.store.store_authorization(auth)

        # 2. Worker readiness check
        worker = IsolatedWorker(
            worker_inventory_for_plan(self.plan, worker_identity="worker-test-01"),
            TestApprovalControl(self.store, trust_store, engagement),
            TestExecutionSandbox(),
        )
        self.assertEqual(worker.config.worker_id, "worker-test-01")

        # 3. Retrieve stored authorization
        retrieved = self.store.get_authorization(auth.authorization_id)
        self.assertEqual(retrieved.status, "approved")

        # 4. Atomic consume
        consumed = self.store.atomically_consume(
            auth.authorization_id,
            worker_identity="worker-test-01",
            expected_authorization=auth,
        )
        self.assertEqual(consumed.status, "consumed")


if __name__ == "__main__":
    unittest.main()
