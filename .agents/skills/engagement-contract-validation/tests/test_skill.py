"""Tests for engagement-contract-validation skill."""

from pathlib import Path
import unittest

from cops.contracts import (
    ContractError,
    validate_contract,
    validate_transition,
)

FIXTURES_DIR = Path(__file__).resolve().parents[4] / "cops" / "contracts" / "fixtures"


class TestEngagementContractValidationSkill(unittest.TestCase):
    def test_skill_file_exists(self):
        skill_path = Path(__file__).resolve().parents[1] / "SKILL.md"
        self.assertTrue(skill_path.is_file())
        content = skill_path.read_text(encoding="utf-8")
        self.assertIn("name: engagement-contract-validation", content)
        self.assertIn("description:", content)

    def test_lifecycle_transitions(self):
        # Valid
        validate_transition("planned", "active", "engagement")
        validate_transition("active", "completed", "engagement")
        validate_transition("draft", "pending_approval", "action_plan")

        # Invalid
        with self.assertRaises(ContractError) as ctx:
            validate_transition("completed", "active", "engagement")
        self.assertEqual(ctx.exception.code, "illegal_transition")

        with self.assertRaises(ContractError) as ctx:
            validate_transition("rejected", "executing", "action_plan")
        self.assertEqual(ctx.exception.code, "illegal_transition")


if __name__ == "__main__":
    unittest.main()
