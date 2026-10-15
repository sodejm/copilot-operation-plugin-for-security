"""Authorization conclusions require complete, consistent replay evidence."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from cops.web_api.assessment import (
    AssessmentVerdict,
    AuthorizationCase,
    assess_object_authorization,
    assess_rate_limit,
)
from cops.web_api.models import ReplayResponse


def complete_cases() -> list[AuthorizationCase]:
    cases = []
    for surface in ("rest", "graphql"):
        for actor in ("owner", "other", "anonymous"):
            request_id = f"{surface}-{actor}"
            allowed = actor == "owner"
            document = {"data": {"object": {"id": "object"}}} if allowed else {
                "data": {"object": None}, "errors": [{"extensions": {"code": "FORBIDDEN"}}],
            }
            response = ReplayResponse(request_id, 200 if surface == "graphql" or allowed else 403,
                                      {}, json.dumps(document))
            cases.append(AuthorizationCase(request_id, surface, actor, "object", allowed, response))
    return cases


def test_complete_corrected_replays_pass() -> None:
    assert assess_object_authorization(complete_cases()).verdict == AssessmentVerdict.PASS


@pytest.mark.parametrize("document", [
    {"errors": [{"message": "internal server error"}]},
    {"data": {"object": None}, "errors": [{"extensions": {"code": "NOT_FOUND"}}]},
    {"data": {"object": None}, "errors": [{"extensions": {"code": "FORBIDDEN"}}, {}]},
    {"data": {"object": None}},
    [],
])
def test_graphql_errors_do_not_establish_denial(document: object) -> None:
    cases = complete_cases()
    cases[-1] = replace(cases[-1], response=replace(cases[-1].response, body_excerpt=json.dumps(document)))
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.INSUFFICIENT_EVIDENCE


def test_partial_graphql_leak_is_a_failure_even_with_forbidden_error() -> None:
    cases = complete_cases()
    document = {"data": {"object": {"id": "object"}}, "errors": [{"extensions": {"code": "FORBIDDEN"}}]}
    cases[-1] = replace(cases[-1], response=replace(cases[-1].response, body_excerpt=json.dumps(document)))
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.FAIL


@pytest.mark.parametrize("mutation", ["duplicate", "object", "request", "expectation", "transport", "deep_json"])
def test_inconsistent_authorization_evidence_is_inconclusive(mutation: str) -> None:
    cases = complete_cases()
    if mutation == "duplicate":
        cases.append(cases[-1])
    elif mutation == "object":
        cases[-1] = replace(cases[-1], object_id="different")
    elif mutation == "request":
        cases[-1] = replace(cases[-1], response=replace(cases[-1].response, request_id="different"))
    elif mutation == "expectation":
        cases[-1] = replace(cases[-1], expected_allowed=True)
    elif mutation == "transport":
        cases[-1] = replace(cases[-1], response=replace(cases[-1].response, replay_success=False))
    else:
        cases[-1] = replace(cases[-1], response=replace(cases[-1].response, body_excerpt="[" * 1500 + "]" * 1500))
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize("failure", ["duplicate", "transport", "exception"])
def test_throttling_requires_independent_successful_replays(failure: str) -> None:
    responses = [ReplayResponse(str(i), 200 if i < 2 else 429, {"Retry-After": "1"}, "") for i in range(3)]
    assert assess_rate_limit(responses).verdict == AssessmentVerdict.PASS
    if failure == "duplicate":
        responses[-1] = replace(responses[-1], request_id="0")
    elif failure == "transport":
        responses[0] = replace(responses[0], replay_success=False)
    else:
        responses[0] = replace(responses[0], error_message="transport interrupted")
    assert assess_rate_limit(responses).verdict == AssessmentVerdict.INSUFFICIENT_EVIDENCE
