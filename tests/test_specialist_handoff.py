"""Unit tests for specialist routing and bounded Triad workflow handoffs."""

from __future__ import annotations

import io
import json
import sys
import unittest

from cops.catalog import ROOT
from cops.contracts.validation import validate_contract
from cops.engagement.cli import command_engagement_handoff
from cops.routing import (
    AuthorizationExpansionError,
    ConflictingEvidenceError,
    InvalidHandoffResultError,
    MaterialPlanModifiedError,
    MissingCapabilityError,
    accept_specialist_handoff,
    audit_and_approve_handoff,
    execute_triad_handoff_workflow,
    propose_specialist_handoff,
    review_with_skeptic,
)


class TestSpecialistWorkflowHandoff(unittest.TestCase):
    """Test suite for structured Triad handoffs between planner, specialist, skeptic, and auditor."""

    def setUp(self) -> None:
        self.engagement = {
            "schema_version": "cops.engagement/v1",
            "engagement_id": "eng-triad-01",
            "name": "Triad Workflow Assessment",
            "status": "active",
            "mode": "planning",
            "scope": {
                "included_targets": ["10.100.1.10", "app.corp.internal"],
                "excluded_targets": ["10.100.1.1"],
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
                "max_duration_hours": 8,
                "max_target_count": 2,
            },
        }

        self.action_plan = {
            "schema_version": "cops.action-plan/v1",
            "plan_id": "plan-triad-01",
            "engagement_id": "eng-triad-01",
            "scenario_id": "COPS-E03.02-S01",
            "target": "10.100.1.10",
            "specialist_id": "cops-pentest-specialist",
            "status": "approved",
            "limits": {
                "max_duration_seconds": 3600,
                "rate_limit_rps": 10,
            },
            "operations": [
                {
                    "step_id": "step-01",
                    "tool": "nmap",
                    "action": "port_scan",
                    "arguments": {"target": "10.100.1.10", "ports": "80,443"},
                }
            ],
            "digest": "sha256:dummyplan00000000000000000000000000000000000000000000000000000000",
            "operator": "secops-lead",
            "rules_of_engagement": {
                "allowed_actions": ["discovery", "port_scan"],
            },
        }

    def test_full_triad_workflow_success(self) -> None:
        """Verify standard successful Triad workflow from proposal to audit completion."""
        # 1. Proposal
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Perform authorized network reconnaissance against 10.100.1.10",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["reconnaissance", "port scan"],
        )
        self.assertEqual(handoff.status, "proposed")
        self.assertEqual(handoff.approval_status, "approved")
        self.assertEqual(handoff.recipient["specialist_id"], "cops-pentest-specialist")
        self.assertTrue(handoff.material_plan_digest.startswith("sha256:"))
        validate_contract(handoff.to_dict(), "specialist_handoff")

        # 2. Acceptance by specialist
        accepted = accept_specialist_handoff(handoff, "cops-pentest-specialist")
        self.assertEqual(accepted.status, "accepted")
        self.assertEqual(len(accepted.transition_log), 2)
        validate_contract(accepted.to_dict(), "specialist_handoff")

        # 3. Skeptic review
        evidence = [
            {
                "envelope_id": "env-01",
                "subject": "10.100.1.10",
                "fact": "ports_open_80_443",
            }
        ]
        in_review = review_with_skeptic(
            accepted,
            "cops-threat-hunter",
            evidence_envelopes=evidence,
            findings=["open-ports-80-443"],
        )
        self.assertEqual(in_review.status, "in_review")
        self.assertIn("env-01", in_review.evidence["evidence_envelopes"])
        self.assertIn("open-ports-80-443", in_review.evidence["findings"])
        validate_contract(in_review.to_dict(), "specialist_handoff")

        # 4. Auditor audit & approve
        completed = audit_and_approve_handoff(
            in_review,
            "cops-compliance-auditor",
            self.action_plan,
        )
        self.assertEqual(completed.status, "completed")
        self.assertEqual(completed.approval_status, "approved")
        validate_contract(completed.to_dict(), "specialist_handoff")

    def test_missing_capability_rejection(self) -> None:
        """Specialist must reject handoff when missing required capabilities."""
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Execute specialized physical lock picking and drone surveillance",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["drone-surveillance-v2", "physical-bypass"],
        )
        with self.assertRaises(MissingCapabilityError) as ctx:
            accept_specialist_handoff(handoff, "cops-pentest-specialist")
        self.assertIn("drone-surveillance-v2", str(ctx.exception))
        self.assertEqual(handoff.status, "rejected")
        self.assertIsNotNone(handoff.rejection_reason)

    def test_conflicting_evidence_rejection(self) -> None:
        """Domain Skeptic must reject handoffs with contradictory evidence envelopes."""
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Inspect host reachability",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["reconnaissance"],
        )
        accept_specialist_handoff(handoff, "cops-pentest-specialist")

        # Contradictory evidence: host is claimed to be offline and online
        contradictory = [
            {"envelope_id": "env-01", "subject": "10.100.1.10", "fact": "host_offline"},
            {"envelope_id": "env-02", "subject": "10.100.1.10", "fact": "host_online_active"},
        ]
        with self.assertRaises(ConflictingEvidenceError):
            review_with_skeptic(
                handoff,
                "cops-threat-hunter",
                evidence_envelopes=contradictory,
            )
        self.assertEqual(handoff.status, "rejected")

    def test_skeptic_explicit_objection(self) -> None:
        """Domain Skeptic can register an explicit objection to reject handoff."""
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Verify host services",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["reconnaissance"],
        )
        accept_specialist_handoff(handoff, "cops-pentest-specialist")

        with self.assertRaises(ConflictingEvidenceError) as ctx:
            review_with_skeptic(
                handoff,
                "cops-threat-hunter",
                objection="Telemetric anomalies indicate possible honeypot artifact",
            )
        self.assertIn("honeypot", str(ctx.exception))
        self.assertEqual(handoff.status, "rejected")

    def test_authorization_expansion_target_divergence(self) -> None:
        """Auditor must reject handoffs attempting to expand target scope beyond approved plan."""
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Perform scanning",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["reconnaissance"],
        )
        accept_specialist_handoff(handoff, "cops-pentest-specialist")
        review_with_skeptic(handoff, "cops-threat-hunter")

        with self.assertRaises(AuthorizationExpansionError) as ctx:
            audit_and_approve_handoff(
                handoff,
                "cops-compliance-auditor",
                self.action_plan,
                candidate_target="10.200.99.99",  # unapproved expanded target
            )
        self.assertIn("target '10.200.99.99' differs", str(ctx.exception))
        self.assertEqual(handoff.status, "rejected")
        self.assertEqual(handoff.approval_status, "reapproval_required")

    def test_authorization_expansion_unapproved_tool(self) -> None:
        """Auditor must reject handoffs introducing unapproved tools."""
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Perform scanning",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["reconnaissance"],
        )
        accept_specialist_handoff(handoff, "cops-pentest-specialist")
        review_with_skeptic(handoff, "cops-threat-hunter")

        candidate_ops = [
            {"step_id": "step-02", "tool": "exploit-framework", "action": "rce"}
        ]
        with self.assertRaises(AuthorizationExpansionError) as ctx:
            audit_and_approve_handoff(
                handoff,
                "cops-compliance-auditor",
                self.action_plan,
                candidate_operations=candidate_ops,
            )
        self.assertIn("unapproved tool 'exploit-framework'", str(ctx.exception))
        self.assertEqual(handoff.status, "rejected")

    def test_material_plan_modified_error(self) -> None:
        """Auditor must raise MaterialPlanModifiedError when material plan fields change."""
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Perform scanning",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["reconnaissance"],
        )
        accept_specialist_handoff(handoff, "cops-pentest-specialist")
        review_with_skeptic(handoff, "cops-threat-hunter")

        # Changing operator from secops-lead to unknown-operator changes the material plan digest
        with self.assertRaises(MaterialPlanModifiedError) as ctx:
            audit_and_approve_handoff(
                handoff,
                "cops-compliance-auditor",
                self.action_plan,
                candidate_operator="unauthorized-intruder",
            )
        self.assertIn("Material plan field changed", str(ctx.exception))
        self.assertEqual(handoff.status, "rejected")
        self.assertEqual(handoff.approval_status, "reapproval_required")

    def test_invalid_handoff_result_empty_deliverable(self) -> None:
        """Auditor must reject handoffs with empty or whitespace deliverable."""
        handoff = propose_specialist_handoff(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Perform scanning",
            sender_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            required_capabilities=["reconnaissance"],
        )
        accept_specialist_handoff(handoff, "cops-pentest-specialist")
        review_with_skeptic(handoff, "cops-threat-hunter")

        # Empty deliverable
        handoff.task["deliverable"] = "   "
        with self.assertRaises(InvalidHandoffResultError):
            audit_and_approve_handoff(
                handoff,
                "cops-compliance-auditor",
                self.action_plan,
            )
        self.assertEqual(handoff.status, "rejected")

    def test_execute_triad_handoff_workflow(self) -> None:
        """Verify the high-level execute_triad_handoff_workflow helper."""
        evidence = [{"envelope_id": "env-triad-01", "subject": "10.100.1.10", "fact": "scanned"}]
        findings = ["recon-complete"]
        final_handoff = execute_triad_handoff_workflow(
            engagement=self.engagement,
            action_plan=self.action_plan,
            task_description="Run discovery and port scan against approved target",
            planner_id="secops-lead",
            specialist_id="cops-pentest-specialist",
            evidence_envelopes=evidence,
            findings=findings,
        )
        self.assertEqual(final_handoff.status, "completed")
        self.assertEqual(final_handoff.approval_status, "approved")
        self.assertEqual(len(final_handoff.transition_log), 4)

    def test_cli_handoff_commands(self) -> None:
        """Verify engagement handoff CLI subcommands."""
        import argparse

        # 1. CLI propose
        propose_args = argparse.Namespace(
            handoff_command="propose",
            engagement=json.dumps(self.engagement),
            plan=json.dumps(self.action_plan),
            task="Execute reconnaissance",
            planner="secops-lead",
            specialist="cops-pentest-specialist",
            capabilities="reconnaissance,port scan",
            output=None,
            json=True,
        )
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = command_engagement_handoff(propose_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(rc, 0)
        handoff_data = json.loads(out)
        self.assertEqual(handoff_data["status"], "proposed")
        handoff_json = json.dumps(handoff_data)

        # 2. CLI accept
        accept_args = argparse.Namespace(
            handoff_command="accept",
            handoff=handoff_json,
            specialist="cops-pentest-specialist",
            output=None,
            json=True,
        )
        sys.stdout = io.StringIO()
        try:
            rc = command_engagement_handoff(accept_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(rc, 0)
        accepted_data = json.loads(out)
        self.assertEqual(accepted_data["status"], "accepted")
        accepted_json = json.dumps(accepted_data)

        # 3. CLI review
        review_args = argparse.Namespace(
            handoff_command="review",
            handoff=accepted_json,
            skeptic="cops-threat-hunter",
            evidence=["env-cli-01"],
            findings=["scan-findings"],
            output=None,
            json=True,
        )
        sys.stdout = io.StringIO()
        try:
            rc = command_engagement_handoff(review_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(rc, 0)
        reviewed_data = json.loads(out)
        self.assertEqual(reviewed_data["status"], "in_review")
        reviewed_json = json.dumps(reviewed_data)

        # 4. CLI audit
        audit_args = argparse.Namespace(
            handoff_command="audit",
            handoff=reviewed_json,
            auditor="cops-compliance-auditor",
            plan=json.dumps(self.action_plan),
            output=None,
            json=True,
        )
        sys.stdout = io.StringIO()
        try:
            rc = command_engagement_handoff(audit_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(rc, 0)
        audited_data = json.loads(out)
        self.assertEqual(audited_data["status"], "completed")

        # 5. CLI workflow (end-to-end)
        wf_args = argparse.Namespace(
            handoff_command="workflow",
            engagement=json.dumps(self.engagement),
            plan=json.dumps(self.action_plan),
            task="End to end workflow test",
            planner="secops-lead",
            specialist="cops-pentest-specialist",
            output=None,
            json=True,
        )
        sys.stdout = io.StringIO()
        try:
            rc = command_engagement_handoff(wf_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(rc, 0)
        wf_data = json.loads(out)
        self.assertEqual(wf_data["status"], "completed")


if __name__ == "__main__":
    unittest.main()
