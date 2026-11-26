"""Executable acceptance criteria for routing clarification."""

from pytest_bdd import scenarios, then, when

from cops.routing import route_request

scenarios("../../specs/features/routing_clarification.feature")


@when("I ask for help with a pull request diff and no stated goal", target_fixture="decision")
def vague_diff_request():
    return route_request("Can you look at this pull request diff?")


@then("the router asks for the desired outcome and identifies the application security specialist and its tool")
def clarify_source_diff(decision):
    assert decision.status == "clarification_required"
    assert decision.primary_profile is None
    assert "What outcome" in decision.clarification["question"]
    (option,) = decision.clarification["options"]
    assert option["specialist_id"] == "cops-appsec-engineer"
    assert option["tools"] == ["patchreview"]


@when("I request a high-confidence Sentinel query review with a source diff as input", target_fixture="decision")
def conflicting_input():
    return route_request(
        "Review this Microsoft Sentinel KQL query for high ingestion cost",
        input_kinds=("source-diff",),
    )


@then("the router asks which outcome to prioritize without selecting a specialist")
def clarify_conflicting_input(decision):
    assert decision.status == "clarification_required"
    assert decision.primary_profile is None
    assert decision.clarification["question"] == "Which outcome should the review prioritize?"
    assert [option["specialist_id"] for option in decision.clarification["options"]] == [
        "cops-sentinel-kql-engineer",
        "cops-appsec-engineer",
    ]
