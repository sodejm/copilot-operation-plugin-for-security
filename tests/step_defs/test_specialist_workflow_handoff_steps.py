"""Step definitions for specialist routing and bounded Triad workflow handoffs."""

from __future__ import annotations

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.contracts.validation import validate_contract
from cops.routing import (
    accept_specialist_handoff,
    audit_and_approve_handoff,
    execute_triad_handoff_workflow,
    propose_specialist_handoff,
    review_with_skeptic,
)

scenarios("../../specs/features/specialist_workflow_handoff.feature")


@pytest.fixture
def triad_ctx():
    engagement_data = {
        "schema_version": "cops.engagement/v1",
        "engagement_id": "eng-triad-bdd",
        "name": "Triad BDD Assessment",
        "status": "active",
        "mode": "planning",
        "scope": {
            "included_targets": ["10.10.1.5", "srv.corp.internal"],
            "excluded_targets": ["10.10.1.1"],
        },
        "window": {
            "started_at": "2026-10-05T00:00:00Z",
            "authorized_until_utc": "2026-10-05T23:59:59Z",
        },
        "operator": "secops-bdd",
        "rules_of_engagement": {
            "max_intensity": "low",
            "allowed_actions": ["discovery", "port_scan"],
            "emergency_contact": "soc-bdd@corp.internal",
            "safe_mode": True,
        },
        "budget": {
            "max_duration_hours": 4,
            "max_target_count": 2,
        },
    }

    plan_data = {
        "schema_version": "cops.action-plan/v1",
        "plan_id": "plan-triad-bdd",
        "engagement_id": "eng-triad-bdd",
        "scenario_id": "COPS-E03.02-S01",
        "target": "10.10.1.5",
        "specialist_id": "cops-pentest-specialist",
        "status": "approved",
        "limits": {
            "max_duration_seconds": 1800,
            "rate_limit_rps": 10,
        },
        "operations": [
            {
                "step_id": "step-01",
                "tool": "python3 -m cops check attack-surface-planner",
                "action": "port_scan",
                "arguments": {"target": "10.10.1.5"},
            }
        ],
        "digest": "sha256:triad00000000000000000000000000000000000000000000000000000000000",
        "operator": "secops-bdd",
        "rules_of_engagement": {
            "allowed_actions": ["discovery", "port_scan"],
        },
    }

    return {
        "engagement": engagement_data,
        "action_plan": plan_data,
        "handoff": None,
        "error": None,
    }


@given("a valid active engagement and approved action plan")
def setup_valid_engagement_and_plan(triad_ctx):
    assert triad_ctx["engagement"]["status"] == "active"
    assert triad_ctx["action_plan"]["status"] == "approved"


@when(parsers.parse('the complete Triad handoff workflow is executed for task "{task}"'))
def execute_complete_workflow(triad_ctx, task):
    evidence = [{"envelope_id": "env-bdd-01", "subject": "10.10.1.5", "fact": "discovered"}]
    findings = ["bdd-discovery-passed"]
    triad_ctx["handoff"] = execute_triad_handoff_workflow(
        engagement=triad_ctx["engagement"],
        action_plan=triad_ctx["action_plan"],
        task_description=task,
        planner_id="secops-bdd",
        specialist_id="cops-pentest-specialist",
        workflow_skill_id="network-active-discovery",
        capability_id="cops-pentest-specialist",
        evidence_envelopes=evidence,
        findings=findings,
    )


@then(parsers.parse('the handoff reaches status "{status}" with approval status "{approval}"'))
def verify_handoff_status(triad_ctx, status, approval):
    handoff = triad_ctx["handoff"]
    assert handoff.status == status
    assert handoff.approval_status == approval


@then(parsers.parse("the transition log records {count:d} lifecycle transitions"))
def verify_transition_log_count(triad_ctx, count):
    handoff = triad_ctx["handoff"]
    assert len(handoff.transition_log) == count


@then("the handoff satisfies the specialist handoff contract schema")
def verify_handoff_schema(triad_ctx):
    handoff = triad_ctx["handoff"]
    validate_contract(handoff.to_dict(), "specialist_handoff")


@then("the completed handoff contains no execution result")
def verify_no_execution_result(triad_ctx):
    assert "execution_result" not in triad_ctx["handoff"].to_dict()


@given("a proposed handoff without a workflow target")
def setup_handoff_without_workflow_target(triad_ctx):
    triad_ctx["handoff"] = propose_specialist_handoff(
        triad_ctx["engagement"],
        triad_ctx["action_plan"],
        "Review discovery plan",
        "secops-bdd",
        specialist_id="cops-pentest-specialist",
    )


@given("a proposed handoff with a nonexistent workflow skill")
def setup_handoff_with_unknown_workflow_target(triad_ctx):
    triad_ctx["handoff"] = propose_specialist_handoff(
        triad_ctx["engagement"],
        triad_ctx["action_plan"],
        "Review discovery plan",
        "secops-bdd",
        specialist_id="cops-pentest-specialist",
        workflow_skill_id="unknown-workflow",
        capability_id="cops-pentest-specialist",
    )


@given("a proposed handoff requiring unsupported capabilities")
def setup_handoff_missing_capabilities(triad_ctx):
    handoff = propose_specialist_handoff(
        engagement=triad_ctx["engagement"],
        action_plan=triad_ctx["action_plan"],
        task_description="Perform unsupported industrial ICS rootkit deployment",
        sender_id="secops-bdd",
        specialist_id="cops-pentest-specialist",
        required_capabilities=["scada-firmware-exploit-v9", "deep-sea-cable-tap"],
    )
    triad_ctx["handoff"] = handoff


@when("the specialist attempts to accept the handoff")
def attempt_specialist_accept(triad_ctx):
    handoff = triad_ctx["handoff"]
    try:
        accept_specialist_handoff(handoff, "cops-pentest-specialist")
    except Exception as exc:
        triad_ctx["error"] = exc


@then(parsers.parse('the acceptance fails with "{error_type}"'))
def verify_acceptance_failure(triad_ctx, error_type):
    err = triad_ctx["error"]
    assert err is not None
    assert err.__class__.__name__ == error_type


@then(parsers.parse('the handoff status is "{status}"'))
def verify_handoff_current_status(triad_ctx, status):
    handoff = triad_ctx["handoff"]
    assert handoff.status == status


@given("an accepted handoff with contradictory telemetry observations")
def setup_accepted_handoff_with_contradictions(triad_ctx):
    handoff = propose_specialist_handoff(
        engagement=triad_ctx["engagement"],
        action_plan=triad_ctx["action_plan"],
        task_description="Telemetry inspection",
        sender_id="secops-bdd",
        specialist_id="cops-pentest-specialist",
        workflow_skill_id="network-active-discovery",
        capability_id="cops-pentest-specialist",
        required_capabilities=["reconnaissance", "port scan"],
    )
    accept_specialist_handoff(handoff, "cops-pentest-specialist")
    triad_ctx["handoff"] = handoff


@when("the domain skeptic reviews the handoff")
def attempt_skeptic_review_contradictory(triad_ctx):
    handoff = triad_ctx["handoff"]
    contradictory_evidence = [
        {"envelope_id": "env-01", "subject": "10.10.1.5", "fact": "reachable"},
        {"envelope_id": "env-02", "subject": "10.10.1.5", "fact": "unreachable_no_route"},
    ]
    try:
        review_with_skeptic(
            handoff,
            "cops-threat-hunter",
            evidence_envelopes=contradictory_evidence,
        )
    except Exception as exc:
        triad_ctx["error"] = exc


@then(parsers.parse('the skeptic review fails with "{error_type}"'))
def verify_skeptic_failure(triad_ctx, error_type):
    err = triad_ctx["error"]
    assert err is not None
    assert err.__class__.__name__ == error_type


@given("a handoff in review")
def setup_handoff_in_review(triad_ctx):
    handoff = propose_specialist_handoff(
        engagement=triad_ctx["engagement"],
        action_plan=triad_ctx["action_plan"],
        task_description="Target validation",
        sender_id="secops-bdd",
        specialist_id="cops-pentest-specialist",
        workflow_skill_id="network-active-discovery",
        capability_id="cops-pentest-specialist",
        required_capabilities=["reconnaissance", "port scan"],
    )
    accept_specialist_handoff(handoff, "cops-pentest-specialist")
    review_with_skeptic(
        handoff,
        "cops-threat-hunter",
        evidence_envelopes=[{"envelope_id": "env-01", "subject": "10.10.1.5", "fact": "ok"}],
    )
    triad_ctx["handoff"] = handoff


@when("the auditor checks an unapproved candidate target")
def attempt_auditor_target_expansion(triad_ctx):
    handoff = triad_ctx["handoff"]
    try:
        audit_and_approve_handoff(
            handoff,
            "cops-compliance-auditor",
            triad_ctx["action_plan"],
            candidate_target="192.168.1.100",  # Unapproved out-of-scope target
        )
    except Exception as exc:
        triad_ctx["error"] = exc


@then(parsers.parse('the audit fails with "{error_type}"'))
def verify_audit_failure(triad_ctx, error_type):
    err = triad_ctx["error"]
    assert err is not None
    assert err.__class__.__name__ == error_type


@then(parsers.parse('the handoff approval status is "{approval_status}"'))
def verify_handoff_approval_status(triad_ctx, approval_status):
    handoff = triad_ctx["handoff"]
    assert handoff.approval_status == approval_status


@when("the auditor checks with modified material plan fields")
def attempt_auditor_modified_fields(triad_ctx):
    handoff = triad_ctx["handoff"]
    try:
        audit_and_approve_handoff(
            handoff,
            "cops-compliance-auditor",
            triad_ctx["action_plan"],
            candidate_operator="unauthorized-intruder",  # Modified material field
        )
    except Exception as exc:
        triad_ctx["error"] = exc
