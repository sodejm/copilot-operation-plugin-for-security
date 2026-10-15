from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cops.workflows import (
    PurpleTeamHandoffContract,
    WorkflowContractError,
    emit_purple_team_handoff,
    evaluate_purple_team_handoff,
    execute_simple_rule,
)
from cops.workflows.purple import execute_kql_proposal, execute_sigma_proposal


def handoff(*, evidence: bool = True, expected_action: str = "blocked") -> PurpleTeamHandoffContract:
    return emit_purple_team_handoff(
        source_result={"kind": "finding", "ref": "finding://F-17"},
        expected_telemetry=[{"field": "event.action", "value": expected_action}],
        correlation_ids=["corr-17"],
        window={"start": "2026-10-15T12:00:00Z", "end": "2026-10-15T12:05:00Z"},
        evidence_refs=["evidence://F-17"] if evidence else [],
    )


def event(*, action: str = "blocked", correlation_id: str = "corr-17", timestamp: str = "2026-10-15T12:01:00Z"):
    return {"event": {"action": action}, "correlation_id": correlation_id, "timestamp": timestamp}


def alert(**overrides):
    result = event()
    result["alert"] = True
    result.update(overrides)
    return result


def test_purple_handoff_schema_and_contract_are_strict() -> None:
    document = handoff().to_dict()
    schema = json.loads(
        (Path(__file__).parents[1] / "catalog/schemas/purple-team-handoff.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(document)
    document["unexpected"] = True
    assert list(Draft202012Validator(schema).iter_errors(document))
    with pytest.raises(WorkflowContractError):
        PurpleTeamHandoffContract.from_dict(document)


@pytest.mark.parametrize(
    ("telemetry", "alerts", "evidence", "expected_status", "expected_reason"),
    [
        (None, None, True, "instrumentation_gap", "logs_unavailable"),
        ([], [], True, "instrumentation_gap", "expected_telemetry_not_captured"),
        ([event()], None, True, "indeterminate", "alert_evidence_unavailable"),
        ([event()], [], True, "detection_gap", "expected_alert_not_observed"),
        ([event()], [alert()], True, "verified_detection", "telemetry_and_alert_correlated"),
        ([event()], [alert()], False, "indeterminate", "missing_evidence"),
    ],
)
def test_evaluation_status_requires_real_correlated_evidence(
    telemetry, alerts, evidence, expected_status, expected_reason
) -> None:
    result = evaluate_purple_team_handoff(handoff(evidence=evidence), telemetry, alerts)
    assert result["status"] == expected_status
    assert result["reason"] == expected_reason


def test_alert_must_be_actual_correlated_and_within_window() -> None:
    bad_alerts = [
        {**alert(), "alert": False},
        alert(correlation_id="other"),
        alert(timestamp="2026-10-15T13:00:00Z"),
    ]
    result = evaluate_purple_team_handoff(handoff(), [event()], bad_alerts)
    assert result["status"] == "detection_gap"
    assert result["matched_alerts"] == 0
    assert result["rule_proposal"]["sigma"]["title"] == "COPS purple-team correlation proposal"
    assert result["rule_proposal"]["kql"]


def test_generated_rule_executes_against_attack_and_benign_fixtures() -> None:
    attack_fixture = [event(), event(correlation_id="other"), event(action="allowed")]
    benign_fixture = [event(), event(action="allowed")]
    result = evaluate_purple_team_handoff(
        handoff(), [event()], [], attack_fixture=attack_fixture, benign_fixture=benign_fixture
    )

    assert result["fixture_counts"] == {"attack_matches": 2, "benign_matches": 1}
    assert result["rule_execution"]["sigma"]["attack_matches"] == 2
    assert result["rule_execution"]["kql"]["attack_matches"] == 2
    assert result["rule_execution"]["counts_agree"] is True
    assert execute_simple_rule(result["rule"], attack_fixture) == 1


def test_generated_predicate_changes_measured_fixture_counts() -> None:
    attack_fixture = [event(), event(correlation_id="other"), event(action="allowed")]
    benign_fixture = [event(action="allowed")]

    blocked = evaluate_purple_team_handoff(
        handoff(expected_action="blocked"),
        [event()],
        [],
        attack_fixture=attack_fixture,
        benign_fixture=benign_fixture,
    )
    allowed = evaluate_purple_team_handoff(
        handoff(expected_action="allowed"),
        [event(action="allowed")],
        [],
        attack_fixture=attack_fixture,
        benign_fixture=benign_fixture,
    )

    assert blocked["fixture_counts"] == {"attack_matches": 2, "benign_matches": 0}
    assert allowed["fixture_counts"] == {"attack_matches": 1, "benign_matches": 1}
    assert blocked["rule_execution"]["sigma"]["proposal_digest"] != allowed["rule_execution"]["sigma"][
        "proposal_digest"
    ]
    assert blocked["rule_execution"]["kql"]["proposal_digest"] != allowed["rule_execution"]["kql"][
        "proposal_digest"
    ]


def test_supported_sigma_and_kql_subsets_execute_escaped_values() -> None:
    value = 'blocked "quoted" \\ path'
    events = [event(action=value), event(action="other")]
    result = evaluate_purple_team_handoff(
        handoff(expected_action=value),
        [event(action=value)],
        [],
        attack_fixture=events,
    )

    assert execute_sigma_proposal(result["rule_proposal"]["sigma"], events) == 1
    assert execute_kql_proposal(result["rule_proposal"]["kql"], events) == 1


@pytest.mark.parametrize(
    "proposal",
    [
        {"title": "rule", "detection": {"selection": {"event.action": "blocked"}, "condition": "selection or x"}},
        {
            "title": "rule",
            "detection": {
                "selection": {"event.action": "blocked"},
                "condition": "selection",
                "extra": True,
            },
        },
        {"title": "rule", "detection": {"selection": {"bad field": "blocked"}, "condition": "selection"}},
    ],
)
def test_unsupported_sigma_proposals_are_explicit(proposal) -> None:
    with pytest.raises(WorkflowContractError, match="sigma_rule_unsupported"):
        execute_sigma_proposal(proposal, [event()])


@pytest.mark.parametrize(
    "proposal",
    [
        'event.action == "blocked" or event.action == "allowed"',
        'event.action != "blocked"',
        'event.action == "unterminated',
        'event.action == "blocked" and ',
        'event.action == "blocked\nnewline"',
        'event.action == "blocked" and event.action == "allowed"',
    ],
)
def test_unsupported_kql_proposals_are_explicit(proposal) -> None:
    with pytest.raises(WorkflowContractError, match="kql_rule_unsupported"):
        execute_kql_proposal(proposal, [event()])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc["source"].update({"kind": "unknown"}),
        lambda doc: doc.update({"correlation_ids": []}),
        lambda doc: doc["time_window"].update({"end": "2026-10-15T11:00:00Z"}),
        lambda doc: doc["expected_telemetry"].append({"field": "bad field", "value": "x"}),
    ],
)
def test_invalid_handoff_fields_are_rejected(mutate) -> None:
    document = handoff().to_dict()
    mutate(document)
    with pytest.raises(WorkflowContractError):
        PurpleTeamHandoffContract.from_dict(document)


def test_contract_defensively_copies_input_and_output() -> None:
    document = handoff().to_dict()
    contract = PurpleTeamHandoffContract.from_dict(document)
    document["source"]["ref"] = "changed"
    exported = contract.to_dict()
    exported["source"]["ref"] = "also-changed"
    assert contract.to_dict()["source"]["ref"] == "finding://F-17"
