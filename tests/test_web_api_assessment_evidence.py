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
            document = (
                {"data": {"object": {"id": "object"}}}
                if allowed
                else {
                    "data": {"object": None},
                    "errors": [{"extensions": {"code": "FORBIDDEN"}}],
                }
            )
            response = ReplayResponse(
                request_id, 200 if surface == "graphql" or allowed else 403, {}, json.dumps(document)
            )
            cases.append(AuthorizationCase(request_id, surface, actor, "object", allowed, response))
    return cases


def test_complete_corrected_replays_pass() -> None:
    assert assess_object_authorization(complete_cases()).verdict == AssessmentVerdict.PASS


def test_corrected_evidence_survives_digest_only_report_round_trip() -> None:
    cases = complete_cases()
    for _ in range(3):
        cases = [replace(case, response=ReplayResponse.from_dict(case.response.to_dict())) for case in cases]
        assert assess_object_authorization(cases).verdict == AssessmentVerdict.PASS
    for case in cases:
        assert '"data"' not in case.response.body_excerpt
        assert '"errors"' not in case.response.body_excerpt


def test_partial_graphql_disclosure_remains_failure_after_redaction() -> None:
    cases = complete_cases()
    document = {"data": {"object": {"id": "private-object-canary"}}, "errors": [{"extensions": {"code": "FORBIDDEN"}}]}
    response = replace(cases[-1].response, body_excerpt=json.dumps(document))
    sanitized = response.to_dict()
    assert "private-object-canary" not in json.dumps(sanitized)
    cases[-1] = replace(cases[-1], response=ReplayResponse.from_dict(sanitized))
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.FAIL


@pytest.mark.parametrize("value", [0, 1, "false", "FORBIDDEN", {}, []])
def test_graphql_observation_requires_boolean_on_both_boundaries(value) -> None:
    document = ReplayResponse("graphql-owner", 200).to_dict()
    document["graphql_object_access"] = value
    with pytest.raises(ValueError, match="GraphQL observation"):
        ReplayResponse.from_dict(document)
    response = ReplayResponse("graphql-owner", 200)
    response.graphql_object_access = value
    with pytest.raises(ValueError, match="GraphQL observation"):
        response.to_dict()


def test_old_digest_only_reports_do_not_reconstruct_graphql_evidence() -> None:
    cases = complete_cases()
    serialized = cases[-1].response.to_dict()
    serialized.pop("graphql_object_access", None)
    cases[-1] = replace(cases[-1], response=ReplayResponse.from_dict(serialized))
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.INSUFFICIENT_EVIDENCE


def test_claimed_graphql_observation_cannot_override_raw_body_or_http_failure() -> None:
    cases = complete_cases()
    response = cases[-1].response
    response.graphql_object_access = True
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.PASS
    response.status_code = 500
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    "document",
    [
        {"errors": [{"message": "internal server error"}]},
        {"data": {"object": None}, "errors": [{"extensions": {"code": "NOT_FOUND"}}]},
        {"data": {"object": None}, "errors": [{"extensions": {"code": "FORBIDDEN"}}, {}]},
        {"data": {"object": None}, "errors": [{"extensions": {"code": []}}]},
        {"data": {"object": None}, "errors": [{"extensions": {"code": {"unexpected": "value"}}}]},
        {"data": {"object": None}},
        [],
    ],
)
def test_graphql_errors_do_not_establish_denial(document: object) -> None:
    cases = complete_cases()
    cases[-1] = replace(cases[-1], response=replace(cases[-1].response, body_excerpt=json.dumps(document)))
    assert assess_object_authorization(cases).verdict == AssessmentVerdict.INSUFFICIENT_EVIDENCE
    cases[-1] = replace(cases[-1], response=ReplayResponse.from_dict(cases[-1].response.to_dict()))
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
