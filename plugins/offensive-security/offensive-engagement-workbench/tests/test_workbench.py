"""Unit tests for COPS Offensive Engagement Workbench."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from offensive_engagement_workbench.core import run_engagement_plan_workflow  # noqa: E402
from cops.engagement import (  # noqa: E402
    EngagementIntakeError,
    IncompatibleWindowError,
    IncompleteBudgetError,
    IncompleteLiveRequestError,
    MissingOwnerError,
    ScopeAmbiguityError,
    build_action_plan,
    create_engagement_contract,
    validate_engagement_intake,
)


class TestOffensiveEngagementWorkbench(unittest.TestCase):
    """Tests for engagement intake, scope validation, and action plan compilation."""

    def setUp(self) -> None:
        self.fixture_path = PACKAGE_ROOT / "fixtures" / "synthetic" / "engagement.json"
        self.valid_data = json.loads(self.fixture_path.read_text(encoding="utf-8"))

    def test_workflow_execution(self) -> None:
        res = run_engagement_plan_workflow(self.fixture_path, root=REPO_ROOT)
        self.assertEqual(res["status"], "passed")
        self.assertEqual(res["network_requests"], 0)
        self.assertEqual(res["mode"], "planning")
        self.assertGreaterEqual(res["operations_count"], 1)
        self.assertIn("Operating System: linux", res["platform_prerequisites"])

    def test_accepted_bounded_engagement(self) -> None:
        eng = create_engagement_contract(
            name="Bounded Test Engagement",
            operator="secops-analyst-01",
            included_targets=["192.168.1.10", "app.corp.internal"],
            excluded_targets=["192.168.1.1"],
            started_at="2026-10-05T00:00:00Z",
            authorized_until_utc="2026-10-05T12:00:00Z",
            allowed_actions=["port_scan", "discovery"],
            budget={"max_duration_seconds": 1200, "max_output_bytes": 1048576},
            mode="planning",
        )
        self.assertEqual(eng.status, "planned")
        self.assertEqual(eng.operator, "secops-analyst-01")

        plan = build_action_plan(
            engagement=eng,
            scenario="COPS-E03.01-S01",
            target="192.168.1.10",
            root=REPO_ROOT,
        )
        self.assertEqual(plan.target, "192.168.1.10")
        self.assertEqual(plan.limits["max_duration_seconds"], 1200)
        self.assertEqual(len(plan.operations), 1)
        self.assertIn("COPS-E03.01-S01_evidence_receipt", plan.operations[0]["expected_evidence"])
        self.assertIn("planning_telemetry_probes", plan.operations[0]["side_effects"])
        self.assertEqual(plan.operations[0]["cleanup"]["action"], "cleanup_temporary_artifacts")

    def test_rejected_missing_owner(self) -> None:
        data = dict(self.valid_data)
        data["operator"] = "   "
        with self.assertRaises(MissingOwnerError):
            validate_engagement_intake(data)

    def test_rejected_ambiguous_target_wildcard(self) -> None:
        data = dict(self.valid_data)
        data["scope"] = {"included_targets": ["*"], "excluded_targets": []}
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

    def test_rejected_ambiguous_target_collision(self) -> None:
        data = dict(self.valid_data)
        data["scope"] = {
            "included_targets": ["10.100.0.10"],
            "excluded_targets": ["10.100.0.10"],
        }
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

    def test_rejected_incomplete_budget(self) -> None:
        data = dict(self.valid_data)
        data["budget"] = {"max_duration_seconds": -1, "max_output_bytes": 1000}
        with self.assertRaises(IncompleteBudgetError):
            validate_engagement_intake(data)

    def test_rejected_incompatible_window(self) -> None:
        data = dict(self.valid_data)
        data["window"] = {
            "started_at": "2026-10-05T12:00:00Z",
            "authorized_until_utc": "2026-10-05T08:00:00Z",
        }
        with self.assertRaises(IncompatibleWindowError):
            validate_engagement_intake(data)

    def test_refuse_incomplete_live_request(self) -> None:
        data = dict(self.valid_data)
        data["mode"] = "live"
        data["budget"] = None  # Live mode requires budget
        with self.assertRaises(IncompleteLiveRequestError):
            validate_engagement_intake(data)


if __name__ == "__main__":
    unittest.main()
