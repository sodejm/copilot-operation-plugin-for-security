"""Tests for scenario-laboratory-management contributor skill."""

from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from cops.execution.store import ApprovalStore
from cops.laboratory import (
    LaboratoryHarness,
    make_inert_action_plan,
    make_inert_container_environment,
    make_inert_execution_authorization,
)


class TestScenarioLaboratoryManagementSkill(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="cops-skill-lab-")
        self.temp_path = Path(self.temp_dir.name)
        self.store = ApprovalStore(self.temp_path / "approvals.sqlite3")
        self.harness = LaboratoryHarness(store=self.store)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scenario_laboratory_workflow(self):
        # 1. Register and verify environment
        env = make_inert_container_environment()
        verified_env = self.harness.verify_environment(env)
        self.assertEqual(verified_env.status, "verified")
        self.assertTrue(verified_env.canary["verified"])

        # 2. Reproducible reset
        reset_env = self.harness.reproducible_reset(verified_env)
        self.assertEqual(reset_env.status, "verified")

        # 3. Controlled case execution with authorization
        plan = make_inert_action_plan()
        auth = make_inert_execution_authorization(plan)
        result = self.harness.execute_case(
            environment=reset_env,
            action_plan=plan,
            authorization=auth,
            case_type="positive",
        )
        self.assertEqual(result.status, "success")
        self.assertTrue(result.canary_verified)
        self.assertIsNotNone(result.cleanup_receipt)
        self.assertEqual(result.cleanup_receipt.status, "completed")


if __name__ == "__main__":
    unittest.main()
