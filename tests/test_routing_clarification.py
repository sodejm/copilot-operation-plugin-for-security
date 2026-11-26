"""Exercise evidence hints through routing and its public entry points."""

import json

import pytest

from cops.cli import main
from cops.routing import ClassifierResponse, route_request
from cops.routing.cli import main as routing_main


@pytest.mark.parametrize(
    ("query", "kind", "specialist"),
    [
        ("Can you take a look?", "source-diff", "cops-appsec-engineer"),
        ("Can you take a look?", "alert", "cops-soc-analyst"),
        ("Can you look at this PR diff?", None, "cops-appsec-engineer"),
        ("Can you look at this sign-in alert?", None, "cops-soc-analyst"),
        ("Can you look at this incident timeline?", None, "cops-incident-responder"),
        ("Can you look at this detection rule?", None, "cops-detection-engineer"),
        ("Can you look at this KQL query?", None, "cops-sentinel-kql-engineer"),
        ("Can you look at this policy document?", None, "cops-compliance-auditor"),
    ],
)
def test_vague_ask_gets_evidence_specific_guidance(query, kind, specialist):
    decision = route_request(query, input_kinds=(kind,) if kind else ())
    assert decision.primary_profile is None
    assert decision.status == "clarification_required"
    (option,) = decision.clarification["options"]
    assert option["specialist_id"] == specialist
    assert option["suggested_input"]
    assert option["tools"]


def test_file_format_alone_does_not_suggest_specialist_tools():
    decision = route_request("Can you look at this CSV?")
    assert decision.status == "clarification_required"
    assert not decision.clarification["options"]
    assert "source-diff" in decision.clarification["supported_input_kinds"]


def test_classifier_is_not_called_when_evidence_leaves_a_choice():
    calls = []

    def classifier(request):
        calls.append(request)
        return ClassifierResponse("cops-appsec-engineer", 1.0, tokens_used=1)

    decision = route_request(
        "Can you take a look?",
        input_kinds=("source-diff", "alert"),
        optional_classifier=classifier,
        classifier_model="test-model",
        classifier_deadline_ms=100,
        classifier_token_budget=50,
    )
    assert not calls
    assert decision.primary_profile is None
    assert {option["specialist_id"] for option in decision.clarification["options"]} == {
        "cops-appsec-engineer",
        "cops-soc-analyst",
    }


@pytest.mark.parametrize(
    "query",
    ["cops-sentinel-kql-engineer", "Review this Microsoft Sentinel KQL query for high ingestion cost"],
)
def test_goal_and_matching_evidence_allow_routing(query):
    decision = route_request(query, input_kinds=("sentinel-query", "sentinel-query"))
    assert decision.status == "routed"
    assert decision.primary_profile.id == "cops-sentinel-kql-engineer"


def test_exact_profile_id_preserves_intentional_selection():
    decision = route_request("cops-sentinel-kql-engineer", input_kinds=("source-diff",))
    assert decision.status == "routed"
    assert decision.primary_profile.id == "cops-sentinel-kql-engineer"


@pytest.mark.parametrize(("entry", "command"), [(main, "route"), (main, "explain"), (routing_main, "route")])
def test_cli_evidence_guidance(entry, command, capsys):
    args = [command, "Can you take a look?", "--input-kind", "source-diff"]
    assert entry([*args, "--json"]) == 0
    json_output = json.loads(capsys.readouterr().out)
    decision = json_output["routing"] if command == "explain" else json_output
    (option,) = decision["clarification"]["options"]
    assert option["tools"] == ["patchreview"]
    assert option["specialist_id"] == "cops-appsec-engineer"
    assert entry(args) == 0
    output = capsys.readouterr().out
    assert "Suggested input" in output
    assert "patchreview" in output
