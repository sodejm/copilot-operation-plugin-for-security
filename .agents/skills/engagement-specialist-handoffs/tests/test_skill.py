"""Tests for engagement-specialist-handoffs contributor skill."""

from __future__ import annotations

import unittest

from cops.catalog import ROOT
from cops.engagement import build_action_plan, create_engagement_contract
from cops.routing.handoff import (
    accept_specialist_handoff,
    audit_and_approve_handoff,
    execute_triad_handoff_workflow,
    propose_specialist_handoff,
    review_with_skeptic,
)


class TestEngagementSpecialistHandoffsSkill(unittest.TestCase):
    def setUp(self):
        self.engagement = create_engagement_contract(
            name="Specialist Handoff Test Engagement",
            operator="secops-lead",
            included_targets=["10.0.0.10"],
            started_at="2026-10-05T00:00:00Z",
            authorized_until_utc="2026-10-05T12:00:00Z",
            mode="planning",
        )
        self.action_plan = build_action_plan(
            engagement=self.engagement,
            scenario="COPS-E03.01-S01",
            target="10.0.0.10",
            specialist_id="cops-pentest-specialist",
            tool_versions={"python3": "3.11.9"},
            root=ROOT,
        )

    def test_triad_handoff_flow(self):
        # 1. Propose handoff
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Execute network perimeter assessment on authorized host",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            workflow_skill_id="network-active-discovery",
            capability_id="cops-pentest-specialist",
        )
        self.assertEqual(handoff.status, "proposed")
        self.assertEqual(handoff.recipient["specialist_id"], "cops-pentest-specialist")

        # 2. Specialist acceptance
        accept_specialist_handoff(handoff, specialist_id="cops-pentest-specialist")
        self.assertEqual(handoff.status, "accepted")

        # 3. Skeptic review
        review_with_skeptic(
            handoff,
            skeptic_id="cops-threat-hunter",
            evidence_envelopes=[{"envelope_id": "env-001", "subject": "10.0.0.10", "fact": "port-80-open"}],
            findings=["find-001"],
        )
        self.assertEqual(handoff.status, "in_review")

        # 4. Auditor audit & approve
        audit_and_approve_handoff(
            handoff,
            auditor_id="cops-compliance-auditor",
            approved_action_plan=self.action_plan,
        )
        self.assertEqual(handoff.status, "completed")
        self.assertEqual(handoff.approval_status, "approved")

    def test_workflow_convenience_function(self):
        completed = execute_triad_handoff_workflow(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Network port and service discovery review",
            planner_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            workflow_skill_id="network-active-discovery",
            capability_id="cops-pentest-specialist",
        )
        self.assertEqual(completed.status, "completed")
        self.assertEqual(completed.approval_status, "approved")


if __name__ == "__main__":
    unittest.main()
