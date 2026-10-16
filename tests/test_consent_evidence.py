from __future__ import annotations

import copy
import json

import pytest

from cops.laboratory.service_lab import FIXTURE_DIRECTORY
from cops.workflows.consent_evidence import assess_consent


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
    assert result["evidence_refs"] == ["fixture:grant-attack-001", "fixture:signin-attack-001", "fixture:sp-attack-001"]
    assert source == before


def test_corrected_permissions_clear_observation_with_complete_evidence():
    source = evidence()
    source["grants"][0]["high_privilege"] = False
    result = assess_consent(source)
    assert result["status"] == "no_suspicious_consent_observed"
    assert result["targets"] == []


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
    assert result["limitations"]
