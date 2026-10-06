"""Tests for engagement-intake-and-planning contributor skill."""

from __future__ import annotations

from pathlib import Path
import unittest

from cops.catalog import ROOT
from cops.engagement import (
    build_action_plan,
    create_engagement_contract,
    validate_engagement_intake,
)


class TestEngagementIntakeAndPlanningSkill(unittest.TestCase):
    def test_skill_flow(self):
        # 1. Intake creation and validation
        eng = create_engagement_contract(
            name="Contributor Skill Flow",
            operator="secops-lead",
            included_targets=["10.0.0.10"],
            started_at="2026-10-05T00:00:00Z",
            authorized_until_utc="2026-10-05T12:00:00Z",
            budget={"max_duration_seconds": 1800, "max_output_bytes": 5000000},
            mode="planning",
        )
        self.assertEqual(eng.operator, "secops-lead")
        self.assertEqual(eng.mode, "planning")

        # 2. Plan compilation
        plan = build_action_plan(
            engagement=eng,
            scenario="COPS-E03.01-S01",
            target="10.0.0.10",
            specialist_id="cops-pentest-specialist",
            root=ROOT,
        )
        self.assertEqual(plan.target, "10.0.0.10")
        self.assertTrue(len(plan.operations) >= 1)
        self.assertTrue(len(plan.platform_prerequisites) >= 1)
        self.assertIn("cleanup", plan.operations[0])


if __name__ == "__main__":
    unittest.main()
