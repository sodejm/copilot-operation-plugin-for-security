"""Pure execution-preview contract tests."""

from __future__ import annotations

import pytest

from cops.preview import PreviewAction, PreviewBudget, build_execution_preview
from cops.routing import route_request


def test_preview_orders_specialists_and_reports_exact_effects_without_execution() -> None:
    decision = route_request("Plan an authorized penetration test under rules of engagement")
    primary = decision.primary_profile.id
    action = PreviewAction(
        specialist_id=primary,
        action="analyze approved scope",
        reads=("scope/targets.json",),
        writes=("evidence/findings.json",),
        destinations=("local:evidence/findings.json",),
        authorization="interactive authorization required before execution",
        expected_evidence=("signed authorization receipt", "findings JSON"),
        noise="bounded probes may appear in target logs",
    )

    preview = build_execution_preview(
        decision,
        actions={primary: (action,)},
        budget=PreviewBudget(model="gpt-explicit", token_limit=5000, time_limit_seconds=300, cost_limit=2.5),
    )
    document = preview.to_dict()

    assert document["specialists"] == [
        decision.triad_plan.primary.specialist_id,
        decision.triad_plan.skeptic.specialist_id,
        decision.triad_plan.auditor.specialist_id,
    ]
    assert document["actions"][0]["effects"] == {
        "reads": ["scope/targets.json"],
        "writes": ["evidence/findings.json"],
    }
    assert document["actions"][0]["destinations"] == ["local:evidence/findings.json"]
    assert document["budget"]["model"] == "gpt-explicit"
    assert not document["side_effects_performed"]
    assert not document["approvals_consumed"]
    assert not document["connectors_invoked"]
    assert not document["workers_started"]
    assert not document["state_written"]


def test_preview_uses_explicit_unknowns_and_preserves_input_mappings() -> None:
    decision = route_request("Write a KQL query for Sentinel")
    actions: dict = {}
    before = dict(actions)

    preview = build_execution_preview(decision, actions=actions)
    document = preview.to_dict()

    assert actions == before
    assert document["actions"][0]["action"] == "unknown"
    assert document["actions"][0]["destinations"] == ["unknown"]
    assert document["actions"][0]["expected_evidence"] == ["unknown"]
    assert document["actions"][0]["noise"] == "unknown"
    assert set(document["budget"].values()) == {"unknown"}


def test_ambiguous_route_has_empty_nonexecuting_preview() -> None:
    decision = route_request("Please review a general question")
    preview = build_execution_preview(decision).to_dict()

    assert preview["status"] == "clarification_required"
    assert preview["specialists"] == []
    assert preview["actions"] == []
    assert not preview["side_effects_performed"]


def test_preview_rejects_action_registered_under_another_specialist() -> None:
    decision = route_request("Route this request to cops-soc-analyst")
    assert decision.primary_profile is not None

    with pytest.raises(ValueError, match="specialist"):
        build_execution_preview(
            decision,
            actions={
                decision.primary_profile.id: (PreviewAction(specialist_id="different-specialist", action="inspect"),)
            },
        )
