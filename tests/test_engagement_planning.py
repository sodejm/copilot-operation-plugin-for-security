"""Unit tests for COPS engagement intake and execution planning."""

from __future__ import annotations

import argparse
import copy
import io
import json
from pathlib import Path
import sys
import unittest

from cops.catalog import ROOT
from cops.contracts.models import ActionPlan, Engagement
from cops.contracts.validation import validate_contract
from cops.engagement import (
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
from cops.engagement.cli import (
    command_engagement_create,
    command_engagement_info,
    command_engagement_plan,
    command_engagement_validate,
)


class TestEngagementIntakeAndPlanning(unittest.TestCase):
    """Test suite for intake validation, scope enforcement, and action plan compilation."""

    def setUp(self) -> None:
        self.valid_engagement_data = {
            "schema_version": "cops.engagement/v1",
            "engagement_id": "eng-test-unit-01",
            "name": "Production Boundary Assessment",
            "status": "planned",
            "mode": "planning",
            "scope": {
                "included_targets": ["10.200.0.5", "api.corp.internal"],
                "excluded_targets": ["10.200.0.1", "10.200.1.0/24"],
            },
            "window": {
                "started_at": "2026-10-05T00:00:00Z",
                "authorized_until_utc": "2026-10-05T23:59:59Z",
            },
            "operator": "secops-lead",
            "rules_of_engagement": {
                "max_intensity": "low",
                "allowed_actions": ["discovery", "port_scan"],
                "emergency_contact": "soc-alert@corp.internal",
                "safe_mode": True,
            },
            "budget": {
                "max_duration_seconds": 3600,
                "max_output_bytes": 10485760,
            },
            "credential_references": ["app-service-account-key"],
            "created_at": "2026-10-05T00:00:00Z",
        }

    def test_accepted_bounded_engagement(self) -> None:
        """Verify successful intake of a well-formed bounded engagement."""
        validated = validate_engagement_intake(self.valid_engagement_data)
        self.assertEqual(validated["engagement_id"], "eng-test-unit-01")
        self.assertEqual(validated["mode"], "planning")

        eng = Engagement.from_dict(validated)
        self.assertEqual(eng.operator, "secops-lead")
        self.assertEqual(eng.scope["included_targets"], ["10.200.0.5", "api.corp.internal"])
        self.assertEqual(eng.budget["max_duration_seconds"], 3600)

    def test_rejected_missing_owner(self) -> None:
        """Verify rejection when owner/operator is missing or whitespace."""
        data = copy.deepcopy(self.valid_engagement_data)
        data["operator"] = ""
        with self.assertRaises(MissingOwnerError):
            validate_engagement_intake(data)

        data["operator"] = "   \t"
        with self.assertRaises(MissingOwnerError):
            validate_engagement_intake(data)

        del data["operator"]
        with self.assertRaises(MissingOwnerError):
            validate_engagement_intake(data)

    def test_rejected_ambiguous_targets(self) -> None:
        """Verify rejection of ambiguous targets: wildcards, collisions, and invalid syntax."""
        # 1. Wildcard target
        data = copy.deepcopy(self.valid_engagement_data)
        data["scope"]["included_targets"] = ["*"]
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

        # 2. Universal target
        data["scope"]["included_targets"] = ["0.0.0.0/0"]
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

        # 3. Direct collision with exclusions
        data["scope"]["included_targets"] = ["10.200.0.5", "10.200.0.1"]
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

        # 4. Target contained in excluded CIDR
        data["scope"]["included_targets"] = ["10.200.1.50"]  # within 10.200.1.0/24
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

        # 5. Malformed target syntax
        data["scope"]["included_targets"] = ["bad target@@invalid"]
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

        # 6. Empty target
        data["scope"]["included_targets"] = ["   "]
        with self.assertRaises(ScopeAmbiguityError):
            validate_engagement_intake(data)

    def test_rejected_incompatible_window(self) -> None:
        """Verify rejection of incompatible assessment windows."""
        # End precedes start
        data = copy.deepcopy(self.valid_engagement_data)
        data["window"]["started_at"] = "2026-10-05T12:00:00Z"
        data["window"]["authorized_until_utc"] = "2026-10-05T11:00:00Z"
        with self.assertRaises(IncompatibleWindowError):
            validate_engagement_intake(data)

        # Identical start and end
        data["window"]["authorized_until_utc"] = "2026-10-05T12:00:00Z"
        with self.assertRaises(IncompatibleWindowError):
            validate_engagement_intake(data)

        # Invalid timestamp string
        data["window"]["started_at"] = "not-a-timestamp"
        with self.assertRaises(IncompatibleWindowError):
            validate_engagement_intake(data)

    def test_rejected_incomplete_budget(self) -> None:
        """Verify rejection of incomplete or non-positive budget limits."""
        data = copy.deepcopy(self.valid_engagement_data)
        data["budget"] = {"max_duration_seconds": 0, "max_output_bytes": 1000}
        with self.assertRaises(IncompleteBudgetError):
            validate_engagement_intake(data)

        data["budget"] = {"max_duration_seconds": 1000, "max_output_bytes": -50}
        with self.assertRaises(IncompleteBudgetError):
            validate_engagement_intake(data)

        data["budget"] = {"max_duration_seconds": "not-an-int", "max_output_bytes": 1000}
        with self.assertRaises(IncompleteBudgetError):
            validate_engagement_intake(data)

    def test_refuse_incomplete_live_request(self) -> None:
        """Verify strict refusal of live mode requests lacking required constraints."""
        data = copy.deepcopy(self.valid_engagement_data)
        data["mode"] = "live"

        # 1. Refuse live when budget is missing
        data["budget"] = None
        with self.assertRaises(IncompleteLiveRequestError):
            validate_engagement_intake(data)
        data["budget"] = {"max_duration_seconds": 1800, "max_output_bytes": 5000000}

        # 2. Refuse live when operator is placeholder
        data["operator"] = "anonymous"
        with self.assertRaises(IncompleteLiveRequestError):
            validate_engagement_intake(data)
        data["operator"] = "verified-secops"

        # 3. Refuse live when emergency contact is missing or too short
        data["rules_of_engagement"]["emergency_contact"] = "  "
        with self.assertRaises(IncompleteLiveRequestError):
            validate_engagement_intake(data)
        data["rules_of_engagement"]["emergency_contact"] = "emergency@corp.internal"

        # 4. Refuse live when safe_mode is False
        data["rules_of_engagement"]["safe_mode"] = False
        with self.assertRaises(IncompleteLiveRequestError):
            validate_engagement_intake(data)
        data["rules_of_engagement"]["safe_mode"] = True

        # 5. Refuse live when target scope is overly broad (e.g. /16)
        data["scope"]["included_targets"] = ["10.200.0.0/16"]
        with self.assertRaises(IncompleteLiveRequestError):
            validate_engagement_intake(data)

    def test_execution_modes_distinction(self) -> None:
        """Verify distinction between planning, import, laboratory, and live execution modes."""
        for mode in ("planning", "import", "laboratory"):
            data = copy.deepcopy(self.valid_engagement_data)
            data["mode"] = mode
            validated = validate_engagement_intake(data)
            self.assertEqual(validated["mode"], mode)

        # Invalid mode rejected
        data = copy.deepcopy(self.valid_engagement_data)
        data["mode"] = "unsupported_magic_mode"
        with self.assertRaises(EngagementIntakeError):
            validate_engagement_intake(data)

    def test_action_plan_compilation_with_obligations(self) -> None:
        """Verify immutable reviewable ActionPlan compilation with prerequisites and cleanup obligations."""
        eng = create_engagement_contract(
            name="Action Plan Testing Engagement",
            operator="operator-tester",
            included_targets=["10.200.0.5"],
            started_at="2026-10-05T00:00:00Z",
            authorized_until_utc="2026-10-05T12:00:00Z",
            budget={"max_duration_seconds": 1500, "max_output_bytes": 2000000},
            mode="planning",
        )

        plan = build_action_plan(
            engagement=eng,
            scenario="COPS-E03.01-S01",
            target="10.200.0.5",
            specialist_id="cops-pentest-specialist",
            root=ROOT,
        )

        # Verify ActionPlan properties
        self.assertEqual(plan.schema_version, "cops.action-plan/v1")
        self.assertEqual(plan.target, "10.200.0.5")
        self.assertEqual(plan.specialist_id, "cops-pentest-specialist")
        self.assertEqual(plan.status, "draft")

        # Verify platform prerequisites
        self.assertIsNotNone(plan.platform_prerequisites)
        self.assertTrue(any("Operating System" in p for p in plan.platform_prerequisites))
        self.assertTrue(any("Isolated execution worker" in p for p in plan.platform_prerequisites))

        # Verify operations, expected evidence, side effects, cleanup
        self.assertEqual(len(plan.operations), 1)
        op = plan.operations[0]
        self.assertIn("expected_evidence", op)
        self.assertIn("side_effects", op)
        self.assertIn("cleanup", op)
        self.assertEqual(op["cleanup"]["action"], "cleanup_temporary_artifacts")
        self.assertTrue(op["idempotent"])

        # Verify plan contract schema validation
        validated_plan_dict = validate_contract(plan.to_dict(), "action_plan")
        self.assertEqual(validated_plan_dict["plan_digest"], plan.plan_digest)

    def test_cli_create_validate_plan_cycle(self) -> None:
        """Verify end-to-end cycle using CLI handlers."""
        # 1. Test create handler
        create_args = argparse.Namespace(
            name="CLI Test Engagement",
            owner="secops-cli",
            targets="10.50.0.2",
            exclusions="",
            start="2026-10-05T00:00:00Z",
            until="2026-10-05T23:59:59Z",
            allowed_effects="discovery",
            max_intensity="low",
            emergency_contact="soc@corp.net",
            no_safe_mode=False,
            mode="planning",
            budget_duration=1800,
            budget_output_bytes=4000000,
            credentials="",
            id="eng-cli-test-01",
            output=None,
        )
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = command_engagement_create(create_args)
            self.assertEqual(rc, 0)
            created_json = json.loads(sys.stdout.getvalue())
            self.assertEqual(created_json["engagement_id"], "eng-cli-test-01")
        finally:
            sys.stdout = old_stdout

        # 2. Test info and validate handlers
        tmp_file = ROOT / "catalog" / "fixtures" / "test_temp_engagement.json"
        tmp_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            tmp_file.write_text(json.dumps(created_json, indent=2), encoding="utf-8")
            val_args = argparse.Namespace(file=str(tmp_file), json=True)
            self.assertEqual(command_engagement_validate(val_args), 0)

            info_args = argparse.Namespace(file=str(tmp_file), json=True)
            self.assertEqual(command_engagement_info(info_args), 0)

            # 3. Test plan handler
            plan_args = argparse.Namespace(
                engagement=str(tmp_file),
                scenario="COPS-E03.01-S01",
                target="10.50.0.2",
                specialist="cops-pentest-specialist",
                mode="planning",
                output=None,
                json=True,
            )
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                rc_plan = command_engagement_plan(plan_args)
                self.assertEqual(rc_plan, 0)
                plan_json = json.loads(sys.stdout.getvalue())
                self.assertEqual(plan_json["target"], "10.50.0.2")
                self.assertIn("plan_digest", plan_json)
            finally:
                sys.stdout = old_stdout
        finally:
            if tmp_file.exists():
                tmp_file.unlink()


if __name__ == "__main__":
    unittest.main()
