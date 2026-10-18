from __future__ import annotations

import copy
import json

import pytest

from cops.laboratory.service_lab import FIXTURE_DIRECTORY
from cops.workflows.consent_evidence import assess_consent

FIXTURE_EVIDENCE_REFS = [
    "fixture:grant-attack-001",
    "fixture:grant-benign-001",
    "fixture:signin-attack-001",
    "fixture:signin-benign-001",
    "fixture:sp-attack-001",
    "fixture:sp-benign-001",
]


def evidence():
    context = json.loads((FIXTURE_DIRECTORY / "consent-context.json").read_text())
    for key, name in (("grants", "entra-grants.jsonl"), ("signins", "entra-signins.jsonl")):
        context[key] = [json.loads(line) for line in (FIXTURE_DIRECTORY / name).read_text().splitlines()]
    return context


def test_exact_grant_service_principal_application_and_signin_join():
    source = evidence()
    before = copy.deepcopy(source)
    result = assess_consent(source)
    assert result["status"] == "suspicious_consent_observed"
    assert result["targets"] == [{"tenant_id": source["coverage"]["tenant_id"],
                                  "grant_id": "grant-attack-001",
                                  "client_id": source["grants"][0]["client_id"],
                                  "app_id": source["signins"][0]["app_id"]}]
    assert result["targets"][0]["client_id"] != result["targets"][0]["app_id"]
    assert result["evidence_refs"] == FIXTURE_EVIDENCE_REFS
    assert source == before


def test_low_privilege_grants_clear_observation_and_bind_all_assessed_evidence():
    source = evidence()
    for grant in source["grants"]:
        grant["high_privilege"] = False
    before = copy.deepcopy(source)
    result = assess_consent(source)
    assert result["status"] == "no_suspicious_consent_observed"
    assert result["targets"] == []
    assert result["evidence_refs"] == FIXTURE_EVIDENCE_REFS
    assert source == before


def test_nonsuspicious_signins_clear_observation_and_bind_all_assessed_evidence():
    source = evidence()
    for signin in source["signins"]:
        signin["suspicious"] = False
    result = assess_consent(source)
    assert result["status"] == "no_suspicious_consent_observed"
    assert result["targets"] == []
    assert result["evidence_refs"] == FIXTURE_EVIDENCE_REFS


def test_all_matching_signins_are_bound_with_stable_sorted_references():
    source = evidence()
    matching_signin = copy.deepcopy(source["signins"][0])
    matching_signin.update(
        id="signin-attack-002",
        evidence_ref="fixture:signin-attack-002",
        suspicious=False,
    )
    source["signins"].append(matching_signin)
    source["grants"].reverse()
    source["service_principals"].reverse()
    source["signins"].reverse()
    before = copy.deepcopy(source)

    result = assess_consent(source)

    assert result["status"] == "suspicious_consent_observed"
    assert [target["grant_id"] for target in result["targets"]] == ["grant-attack-001"]
    assert result["evidence_refs"] == sorted([*FIXTURE_EVIDENCE_REFS, "fixture:signin-attack-002"])
    assert source == before


def test_unrelated_principal_and_signin_are_not_bound_to_assessed_grants():
    source = evidence()
    unrelated_principal = copy.deepcopy(source["service_principals"][0])
    unrelated_principal.update(
        id="sp-unrelated-001",
        app_id="44444444-4444-4444-4444-444444444444",
        evidence_ref="fixture:sp-unrelated-001",
    )
    unrelated_signin = copy.deepcopy(source["signins"][0])
    unrelated_signin.update(
        id="signin-unrelated-001",
        app_id=unrelated_principal["app_id"],
        evidence_ref="fixture:signin-unrelated-001",
    )
    source["service_principals"].append(unrelated_principal)
    source["signins"].append(unrelated_signin)

    result = assess_consent(source)

    assert result["status"] == "suspicious_consent_observed"
    assert result["evidence_refs"] == FIXTURE_EVIDENCE_REFS


@pytest.mark.parametrize("mutation", [
    lambda e: e["grants"].clear(),
    lambda e: e["signins"].clear(),
    lambda e: e["service_principals"].clear(),
    lambda e: e["signins"][0].update(tenant_id="another-tenant"),
    lambda e: e["signins"][0].update(app_id="another-app"),
    lambda e: e["signins"][0].update(app_id=[]),
    lambda e: e["grants"][0].update(consent_type=[]),
    lambda e: e["grants"][0].update(client_id=e["signins"][0]["app_id"]),
    lambda e: e["signins"][0].update(observed_at="2020-01-01T00:00:00Z"),
    lambda e: e["grants"][0].pop("evidence_ref"),
    lambda e: e["grants"][0].pop("high_privilege"),
    lambda e: e["coverage"].update(signins_complete=False),
    lambda e: e["coverage"].update(window_end="invalid"),
    lambda e: e["signins"].append(copy.deepcopy(e["signins"][0])),
    lambda e: e["service_principals"].append(copy.deepcopy(e["service_principals"][0])),
    lambda e: e["grants"][1].update(principal_id="another-user"),
    lambda e: e["grants"].append("invalid"),
])
def test_missing_or_conflicting_evidence_cannot_clear_or_revoke(mutation):
    source = evidence()
    mutation(source)
    result = assess_consent(source)
    assert result["status"] == "insufficient_evidence"
    assert result["targets"] == []
    assert result["evidence_refs"] == []
    assert result["limitations"]
