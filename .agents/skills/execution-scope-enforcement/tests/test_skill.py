"""Tests for execution-scope-enforcement contributor skill."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cops.execution import ScopeDefinition, ScopeGuard, ScopeViolationError


class TestExecutionScopeEnforcementSkill(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parents[4] / "cops" / "contracts" / "fixtures"
        eng_doc = json.loads((self.fixtures_dir / "valid_engagement.json").read_text(encoding="utf-8"))
        self.scope_def = ScopeDefinition.from_engagement_scope(eng_doc["scope"])
        # Mock resolver for corp.internal
        self.guard = ScopeGuard(
            self.scope_def,
            resolver=lambda host: ["10.0.0.50"] if host == "corp.internal" else ["10.0.0.1"] if host == "prod-db.internal" else [],
        )

    def test_in_scope_destination(self):
        self.guard.check_destination("10.0.0.5")
        self.guard.check_destination("corp.internal")

    def test_excluded_destination(self):
        with self.assertRaises(ScopeViolationError):
            self.guard.check_destination("10.0.0.1")

    def test_cloud_metadata_blocked(self):
        with self.assertRaises(ScopeViolationError):
            self.guard.check_destination("169.254.169.254")


if __name__ == "__main__":
    unittest.main()
