"""Acceptance checks for deterministic detection-quality edge cases."""

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from detectionquality.evaluator import evaluate_fixture_case, evaluate_rule_suite  # noqa: E402
from detectionquality.models import FixtureCase, FixtureSuite, QualityError, Rule  # noqa: E402
from detectionquality.static_analysis import analyze_rule_dependencies  # noqa: E402


@pytest.fixture
def rule() -> Rule:
    path = PLUGIN_ROOT / "rules" / "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN.json"
    return Rule.from_dict(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def joined_rule(rule: Rule) -> Rule:
    join = "SigninLogs | join kind=inner (IdentityRiskEvents) on TenantId, CorrelationId"
    return replace(
        rule,
        source_data={
            "primary_source": "SigninLogs",
            "secondary_sources": ["IdentityRiskEvents"],
            "joins": [join],
            "join_keys": ["TenantId", "CorrelationId"],
        },
        logic={**rule.logic, "query_template": rule.logic["query_template"].replace("SigninLogs", join, 1)},
    )


def sign_in(**changes: object) -> dict[str, object]:
    event: dict[str, object] = {
        "TimeGenerated": "2026-10-01T12:00:00Z",
        "UserPrincipalName": "admin@example.test",
        "IPAddress": "198.51.100.45",
        "ResultType": 0,
        "AppDisplayName": "Azure Portal",
        "TenantId": "tenant-a",
        "CorrelationId": "corr-1",
    }
    event.update(changes)
    return event


def case(case_id: str, events: tuple[dict[str, object], ...], expected: bool, **options: object) -> FixtureCase:
    return FixtureCase.from_dict(
        {
            "case_id": case_id,
            "label": "positive" if expected else "negative",
            "expected_match": expected,
            "events": events,
            **options,
        }
    )


def test_join_requires_matching_tenant_and_correlation(joined_rule: Rule) -> None:
    assert joined_rule.logic["query_template"].startswith(joined_rule.source_data["joins"][0] + " | where ")
    primary = sign_in(source="SigninLogs")
    other_tenant = {"source": "IdentityRiskEvents", "TenantId": "tenant-b", "CorrelationId": "corr-1"}
    same_tenant = {**other_tenant, "TenantId": "tenant-a"}

    rejected = evaluate_fixture_case(case("cross-tenant", (primary, other_tenant), False), joined_rule)
    accepted = evaluate_fixture_case(case("same-tenant", (primary, same_tenant), True), joined_rule)
    unmarked = evaluate_fixture_case(case("unmarked-cross-tenant", (sign_in(), other_tenant), False), joined_rule)

    assert rejected.actual_match is False
    assert rejected.outcome_classification == "true_negative"
    assert accepted.actual_match is True
    assert accepted.outcome_classification == "true_positive"
    assert unmarked.actual_match is False
    assert unmarked.outcome_classification == "true_negative"
    assert (
        analyze_rule_dependencies(joined_rule, [case("joined", (primary, same_tenant), True)])["missing_fields"] == []
    )


def test_synthetic_join_fixture_metrics(joined_rule: Rule) -> None:
    path = PLUGIN_ROOT / "tests" / "fixtures" / "tenant_join.json"
    suite = FixtureSuite.from_dict(json.loads(path.read_text(encoding="utf-8")))
    report = evaluate_rule_suite(joined_rule, suite)
    assert {result["case_id"]: result["outcome_classification"] for result in report["case_results"]} == {
        "CASE-JOIN-CROSS-TENANT": "true_negative",
        "CASE-JOIN-SAME-TENANT": "true_positive",
    }
    assert report["metrics"]["total_cases"] == 2
    assert report["metrics"]["evaluated_cases"] == 2
    assert report["metrics"]["precision_on_labeled_fixtures"] == 1.0
    assert report["metrics"]["recall_on_labeled_fixtures"] == 1.0


def test_null_required_field_is_schema_drift_and_cannot_match(rule: Rule) -> None:
    fixture = case("null-ip", (sign_in(IPAddress=None, RiskLevelDuringSignIn="high"),), False)
    result = evaluate_fixture_case(fixture, rule)

    assert result.actual_match is False
    assert result.outcome_classification == "missing_field_error"
    assert result.missing_fields == ("IPAddress",)
    assert analyze_rule_dependencies(rule, [fixture])["missing_fields"] == ["IPAddress"]


@pytest.mark.parametrize(
    ("event_time", "expected"),
    [
        ("2026-10-01T11:00:00Z", True),
        ("2026-10-01T10:59:59Z", False),
        ("2026-10-01T12:00:01Z", False),
    ],
)
def test_time_window_is_inclusive_and_excludes_future_events(rule: Rule, event_time: str, expected: bool) -> None:
    fixture = case("window", (sign_in(TimeGenerated=event_time),), expected, evaluation_time="2026-10-01T12:00:00Z")
    assert evaluate_fixture_case(fixture, rule).actual_match is expected


def test_invalid_anchor_is_rejected(rule: Rule) -> None:
    fixture = case("bad-anchor", (sign_in(),), True, evaluation_time="yesterday")
    with pytest.raises(QualityError, match="timestamp"):
        evaluate_fixture_case(fixture, rule)


def test_duplicate_events_count_as_one_labeled_case(rule: Rule) -> None:
    event = sign_in()
    fixture = case("duplicate", (event, dict(event)), True)
    report = evaluate_rule_suite(rule, FixtureSuite("duplicates", rule.rule_id, (fixture,)))

    assert report["metrics"]["total_cases"] == 1
    assert report["metrics"]["true_positives"] == 1
    assert report["case_results"][0]["actual_match"] is True


def test_suppression_scopes_to_identity_and_tenant(rule: Rule) -> None:
    alert = {"timestamp": "2026-10-01T11:00:00Z", "identity": "admin@example.test", "tenant_id": "tenant-a"}
    suppressed = case("suppressed", (sign_in(),), False, prior_alerts=[alert])
    other_tenant = case("other-tenant", (sign_in(),), True, prior_alerts=[{**alert, "tenant_id": "tenant-b"}])
    other_user = case("other-user", (sign_in(),), True, prior_alerts=[{**alert, "identity": "other@example.test"}])

    assert evaluate_fixture_case(suppressed, rule).actual_match is False
    assert evaluate_fixture_case(other_tenant, rule).actual_match is True
    assert evaluate_fixture_case(other_user, rule).actual_match is True


def test_unknown_tenant_does_not_suppress(rule: Rule) -> None:
    fixture = case(
        "unknown-tenant",
        (sign_in(TenantId=None),),
        True,
        prior_alerts=[{"timestamp": "2026-10-01T11:00:00Z", "identity": "admin@example.test"}],
    )
    assert evaluate_fixture_case(fixture, rule).actual_match is True


def test_global_suppression_is_explicitly_tenant_wide(rule: Rule) -> None:
    global_rule = replace(rule, identity_scope="global")
    alert = {"timestamp": "2026-10-01T11:00:00Z", "identity": "other@example.test", "tenant_id": "tenant-a"}

    assert (
        evaluate_fixture_case(case("same-tenant", (sign_in(),), False, prior_alerts=[alert]), global_rule).actual_match
        is False
    )
    assert (
        evaluate_fixture_case(
            case("other-tenant", (sign_in(),), True, prior_alerts=[{**alert, "tenant_id": "tenant-b"}]), global_rule
        ).actual_match
        is True
    )


def test_unknown_identity_scope_is_rejected(rule: Rule) -> None:
    with pytest.raises(QualityError, match="identity_scope"):
        Rule.from_dict({**rule.to_dict(), "identity_scope": "uesr"})


def test_suppression_window_boundary(rule: Rule) -> None:
    at_boundary = {"timestamp": "2026-10-01T06:00:00Z", "identity": "admin@example.test", "tenant_id": "tenant-a"}
    before_boundary = {**at_boundary, "timestamp": "2026-10-01T05:59:59Z"}

    assert (
        evaluate_fixture_case(case("at-boundary", (sign_in(),), False, prior_alerts=[at_boundary]), rule).actual_match
        is False
    )
    assert (
        evaluate_fixture_case(
            case("before-boundary", (sign_in(),), True, prior_alerts=[before_boundary]), rule
        ).actual_match
        is True
    )


def test_bundled_edge_case_outcomes_and_metrics(rule: Rule) -> None:
    path = PLUGIN_ROOT / "fixtures" / "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN.json"
    suite = FixtureSuite.from_dict(json.loads(path.read_text(encoding="utf-8")))
    report = evaluate_rule_suite(rule, suite)
    outcomes = {result["case_id"]: result["outcome_classification"] for result in report["case_results"]}

    assert outcomes["CASE-BND-NULL-IP"] == "missing_field_error"
    assert outcomes["CASE-WINDOW-LOWER-BOUND"] == "true_positive"
    assert outcomes["CASE-WINDOW-OUTSIDE"] == "true_negative"
    assert outcomes["CASE-DUPLICATE-EVENT"] == "true_positive"
    assert outcomes["CASE-SUPPRESSED-ALERT"] == "true_negative"
    assert report["metrics"] == {
        "total_cases": 11,
        "evaluated_cases": 9,
        "schema_error_cases": 2,
        "true_positives": 4,
        "false_positives": 0,
        "true_negatives": 5,
        "false_negatives": 0,
        "precision_on_labeled_fixtures": None,
        "recall_on_labeled_fixtures": None,
    }
