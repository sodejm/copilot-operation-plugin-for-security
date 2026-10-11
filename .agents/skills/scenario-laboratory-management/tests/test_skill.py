"""Offline workflow check for the scenario-laboratory-management skill."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.laboratory import (
    LaboratoryCaseJournal,
    LaboratoryHarness,
    make_inert_action_plan,
    make_inert_container_environment,
)
from tests.auth_testkit import authorize_test_plan, worker_inventory_for_plan
from tests.laboratory_testkit import (
    case_observation,
    endpoint_inventory,
    environment_observation,
    observation_trust_store,
    remote_run,
    reset_receipt,
)


class TestScenarioLaboratoryManagementSkill(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="cops-skill-lab-")
        temp_path = Path(self.temp_dir.name).resolve()
        self.inventory = endpoint_inventory(temp_path)
        self.harness = LaboratoryHarness(
            observation_provider=lambda env, nonce: environment_observation(env, nonce, self.inventory),
            observation_trust_store=observation_trust_store(temp_path),
            case_journal=LaboratoryCaseJournal(temp_path / "case-journal.sqlite3"),
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scenario_laboratory_workflow(self):
        environment = make_inert_container_environment()
        self.assertEqual(
            self.harness.verify_environment(environment, endpoint_inventory=self.inventory).status,
            "verified",
        )

        nonce = self.harness.begin_reset(environment)
        self.assertEqual(environment.status, "resetting")
        receipt = reset_receipt(environment, nonce, self.inventory)
        self.assertEqual(
            self.harness.reproducible_reset(
                environment, reset_receipt=receipt, endpoint_inventory=self.inventory
            ).status,
            "verified",
        )

        plan = make_inert_action_plan()
        authorization, trust_store, engagement = authorize_test_plan(plan, worker_identity=environment.owner)
        run = remote_run(plan, authorization.authorization_id, environment.owner)
        with patch("cops.laboratory.harness.SSHExecutionDispatcher.execute", return_value=run):
            authorized_run = self.harness.execute_case(
                environment,
                plan,
                authorization,
                "positive",
                trust_store=trust_store,
                engagement=engagement,
                worker_inventory=worker_inventory_for_plan(plan, worker_identity=environment.owner),
                endpoint_inventory=self.inventory,
                scope_guard=ScopeGuard(ScopeDefinition.from_engagement_scope(engagement.scope)),
            )
        observation = case_observation(
            environment,
            plan,
            authorization.authorization_id,
            authorized_run,
            self.inventory,
            request_nonce=self.harness.case_observation_challenge(authorized_run),
            canary_token_detected=True,
            control_blocked=False,
        )
        result = self.harness.classify_case(
            environment,
            plan,
            authorized_run,
            authorization.authorization_id,
            "positive",
            case_observation=observation,
            endpoint_inventory=self.inventory,
        )
        self.assertEqual(result.status, "success")
        self.assertTrue(result.canary_verified)
        self.assertEqual(result.run_result.cleanup_status, "completed")
        self.assertIsNone(result.cleanup_receipt)


if __name__ == "__main__":
    unittest.main()
