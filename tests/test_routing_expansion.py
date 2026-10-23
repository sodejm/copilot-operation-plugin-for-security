"""Routing-v2 metadata, evaluation, privacy, and failure-boundary tests."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from threading import Event
from time import monotonic

import pytest

from cops.routing import ClassifierResponse, extract_routing_features, load_specialists_registry, route_request

ROOT = Path(__file__).resolve().parents[1]
HELD_OUT = ROOT / "tests" / "fixtures" / "routing-held-out-v1.json"
EXPANSION_TARGETS = {
    "cops-api-security-specialist",
    "cops-cloud-posture-specialist",
    "cops-network-segmentation-specialist",
    "cops-secrets-remediation-specialist",
    "cops-supply-chain-specialist",
    "cops-tls-crypto-specialist",
}


def _profile(profile_id: str, **overrides: object) -> dict[str, object]:
    profile: dict[str, object] = {
        "id": profile_id,
        "display_name": profile_id,
        "domain": "test",
        "criticality": "normal",
        "interactive_authorization_required": False,
        "description": f"Purpose for {profile_id}",
        "primary_plugin": "test-plugin",
        "skills": ["test-skill"],
        "tools": [],
        "contract_file": "agents/test.md",
        "intent_keywords": ["legacy phrase"],
        "symptom_triggers": [],
        "artifact_triggers": [],
        "anti_triggers": [],
        "example_prompts": [],
        "purpose": f"Purpose for {profile_id}",
        "required_permissions": ["read approved evidence"],
    }
    profile.update(overrides)
    return profile


def _registry(tmp_path: Path, *profiles: dict[str, object]) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"specialists": profiles}), encoding="utf-8")
    return path


def test_canonical_triggers_examples_and_anti_triggers_are_consumed(tmp_path: Path) -> None:
    registry = _registry(
        tmp_path,
        _profile(
            "cops-alpha",
            symptom_triggers=["alpha incident"],
            artifact_triggers=["sigma rule"],
            anti_triggers=["training only"],
            example_prompts=["Investigate the alpha production incident"],
        ),
        _profile("cops-beta", symptom_triggers=["beta review"]),
    )

    assert route_request("Handle this alpha incident", registry_path=registry).primary_profile.id == "cops-alpha"
    assert (
        route_request("logsource: x detection: y condition: z", registry_path=registry).primary_profile.id
        == "cops-alpha"
    )
    assert (
        route_request("Investigate the alpha production incident", registry_path=registry).primary_profile.id
        == "cops-alpha"
    )
    decision = route_request("alpha incident training only", registry_path=registry)
    assert decision.status == "clarification_required"


def test_canonical_only_profiles_do_not_require_legacy_intent_keywords(tmp_path: Path) -> None:
    canonical = _profile("cops-canonical", symptom_triggers=["canonical symptom"])
    canonical.pop("intent_keywords")
    registry = _registry(tmp_path, canonical)

    profiles = load_specialists_registry(registry)
    assert profiles[0].intent_keywords == ()
    assert route_request("Review this canonical symptom", registry_path=registry).primary_profile.id == (
        "cops-canonical"
    )


def test_legacy_intent_keywords_remain_a_routing_fallback(tmp_path: Path) -> None:
    registry = _registry(
        tmp_path,
        _profile("cops-legacy", intent_keywords=["legacy routing phrase"]),
    )

    decision = route_request("Please handle this legacy routing phrase", registry_path=registry)
    assert decision.status == "routed"
    assert decision.primary_profile.id == "cops-legacy"


def test_routing_result_is_versioned_ranked_and_exposes_authorization() -> None:
    decision = route_request("Plan an authorized penetration test under rules of engagement")
    document = decision.to_dict()

    assert document["version"] == "cops.routing-decision/v2"
    assert document["status"] == "routed"
    assert document["ranked_candidates"]
    assert document["ranked_candidates"][0]["reasons"]
    assert document["ranked_candidates"][0]["confidence"] >= 0.65
    assert "interactive_authorization_required" in document["ranked_candidates"][0]


def test_low_confidence_and_close_lead_return_reviewable_clarification(tmp_path: Path) -> None:
    registry = _registry(
        tmp_path,
        _profile("cops-alpha", symptom_triggers=["shared artifact"], purpose="Review alpha evidence"),
        _profile("cops-beta", symptom_triggers=["shared artifact"], purpose="Review beta evidence"),
    )

    low = route_request("unrelated request", registry_path=registry)
    assert low.status == "clarification_required"
    assert low.primary_profile is None

    close = route_request("shared artifact", registry_path=registry)
    assert close.status == "clarification_required"
    assert [option["purpose"] for option in close.clarification["options"]] == [
        "Review alpha evidence",
        "Review beta evidence",
    ]
    assert close.clarification["options"][0]["required_permissions"] == ["read approved evidence"]


def test_feature_extraction_is_deterministic_and_redacted() -> None:
    secret_hash = "a" * 64
    prompt = (
        "Check CVE-2026-12345 at 192.0.2.10 and analyst@example.test, hash "
        f"{secret_hash}, AWS account 123456789012, subscription id "
        "12345678-1234-1234-1234-123456789abc, project id sample-cloud-123, "
        "then SecurityEvent | summarize count() and inspect report.pcap. "
        "logsource: windows detection: selection condition: selection"
    )
    features = extract_routing_features(prompt)
    redacted = features.redacted_dict()

    assert set(redacted["labels"]) >= {
        "cve",
        "ipv4_address",
        "email_address",
        "sha256",
        "aws_account_id",
        "azure_subscription_id",
        "gcp_project_id",
        "kql_query",
        "sigma_rule",
        "pcap_file",
    }
    serialized = json.dumps(redacted)
    assert "192.0.2.10" not in serialized
    assert "analyst@example.test" not in serialized
    assert secret_hash not in serialized


@pytest.mark.parametrize("failure", [TimeoutError, ConnectionError, OSError])
def test_optional_classifier_failure_requires_clarification(failure: type[Exception]) -> None:
    def unavailable(_request):
        raise failure("offline")

    decision = route_request(
        "general security question",
        optional_classifier=unavailable,
        classifier_model="explicit-model",
        classifier_deadline_ms=100,
        classifier_token_budget=20,
    )
    assert decision.status == "clarification_required"
    assert "unavailable or timed out" in decision.match_reasons[0]


def test_optional_classifier_receives_redacted_bounded_contract() -> None:
    captured = []

    def classify(request):
        captured.append(request)
        return ClassifierResponse("cops-soc-analyst", 0.8, tokens_used=4)

    decision = route_request(
        "Please help 192.0.2.42 analyst@example.test",
        optional_classifier=classify,
        classifier_model="explicit-model",
        classifier_deadline_ms=100,
        classifier_token_budget=20,
    )

    assert decision.primary_profile.id == "cops-soc-analyst"
    request = captured[0]
    assert request.model == "explicit-model"
    assert request.deadline_ms == 100
    assert request.token_budget == 20
    assert "192.0.2.42" not in json.dumps(request.features)
    assert "analyst@example.test" not in json.dumps(request.features)
    assert set(request.registered_specialist_ids)


@pytest.mark.parametrize(
    ("deadline", "budget", "reason"),
    [
        (None, 10, "requires explicit"),
        (10, None, "requires explicit"),
        (0, 10, "exhausted"),
        (10, 0, "exhausted"),
    ],
)
def test_optional_classifier_requires_explicit_available_limits(deadline, budget, reason) -> None:
    decision = route_request(
        "general security question",
        optional_classifier=lambda _request: ClassifierResponse("cops-soc-analyst", 0.9),
        classifier_model="explicit-model",
        classifier_deadline_ms=deadline,
        classifier_token_budget=budget,
    )
    assert decision.status == "clarification_required"
    assert reason in decision.match_reasons[0]


def test_optional_classifier_rejects_unknown_low_confidence_and_over_budget() -> None:
    cases = (
        ClassifierResponse("cops-unknown", 0.9),
        ClassifierResponse("cops-soc-analyst", 0.64),
        ClassifierResponse("cops-soc-analyst", 0.9, tokens_used=-1),
        ClassifierResponse("cops-soc-analyst", 0.9, tokens_used=11),
    )
    for response in cases:
        decision = route_request(
            "general security question",
            optional_classifier=lambda _request, value=response: value,
            classifier_model="explicit-model",
            classifier_deadline_ms=100,
            classifier_token_budget=10,
        )
        assert decision.status == "clarification_required"


def test_optional_classifier_hanging_adapter_has_a_real_deadline() -> None:
    release = Event()

    def stalled(_request):
        release.wait(5)
        return ClassifierResponse("cops-soc-analyst", 0.9)

    start = monotonic()
    try:
        decision = route_request(
            "general security question",
            optional_classifier=stalled,
            classifier_model="explicit-model",
            classifier_deadline_ms=20,
            classifier_token_budget=10,
        )
        assert decision.status == "clarification_required"
        assert monotonic() - start < 1
    finally:
        release.set()


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        ClassifierResponse("cops-soc-analyst", float("nan")),
        ClassifierResponse("cops-soc-analyst", "0.9"),
        ClassifierResponse("cops-soc-analyst", 0.9, tokens_used=True),
    ],
)
def test_optional_classifier_rejects_malformed_results(response) -> None:
    decision = route_request(
        "general security question",
        optional_classifier=lambda _request: response,
        classifier_model="explicit-model",
        classifier_deadline_ms=100,
        classifier_token_budget=10,
    )
    assert decision.status == "clarification_required"


def test_optional_classifier_reason_cannot_leak_provider_text() -> None:
    decision = route_request(
        "general security question",
        optional_classifier=lambda _request: ClassifierResponse("cops-soc-analyst", 0.9, "secret-value"),
        classifier_model="explicit-model",
        classifier_deadline_ms=100,
        classifier_token_budget=10,
    )
    assert "secret-value" not in json.dumps(decision.to_dict())


def test_held_out_evaluation_meets_accuracy_and_ambiguity_gates() -> None:
    corpus = json.loads(HELD_OUT.read_text(encoding="utf-8"))
    all_clear = corpus["clear"]
    ambiguous = corpus["ambiguous_or_negative"]
    registered_ids = {profile.id for profile in load_specialists_registry()}
    fixture_targets = {row["expected"] for row in all_clear}
    clear = [row for row in all_clear if row["expected"] in registered_ids]
    published = {
        prompt.strip().lower() for profile in load_specialists_registry() for prompt in profile.example_prompts
    }
    assert len(all_clear) >= 270
    assert len(ambiguous) >= 100
    assert registered_ids <= fixture_targets
    assert EXPANSION_TARGETS <= fixture_targets
    active_expansion_targets = registered_ids & EXPANSION_TARGETS
    assert not active_expansion_targets or active_expansion_targets == EXPANSION_TARGETS
    if not active_expansion_targets:
        pytest.skip("routing-v2 held-out gate activates when the expansion profiles are registered")
    assert all(row["query"].strip().lower() not in published for row in clear)

    correct = Counter()
    totals = Counter()
    for row in clear:
        decision = route_request(row["query"])
        actual = decision.primary_profile.id if decision.status == "routed" and decision.primary_profile else None
        totals[row["expected"]] += 1
        correct[row["expected"]] += actual == row["expected"]

    assert set(totals) == registered_ids
    assert sum(correct.values()) / sum(totals.values()) >= 0.95
    assert all(totals[target] >= 10 and correct[target] / totals[target] >= 0.90 for target in totals)
    assert all(route_request(row["query"]).status == "clarification_required" for row in ambiguous)
