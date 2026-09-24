from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "agent"))

from validate_marketplace import ValidationError, validate_finding_document, validate_marketplace


scenarios("../../specs/features/marketplace_portability.feature")


@pytest.fixture
def context() -> dict[str, object]:
    return {}


def verified_example() -> dict[str, object]:
    return json.loads((ROOT / "catalog/examples/verified-finding.json").read_text(encoding="utf-8"))


@given("the repository marketplace catalog")
def repository_catalog(context):
    context["action"] = validate_marketplace


@given("a finding with complete current supporting evidence")
def complete_finding(context):
    context["document"] = verified_example()


@given("a limited-confidence finding without an uncertainty statement")
def limited_finding(context):
    document = verified_example()
    finding = document["findings"][0]
    finding["verification"] = "partially-verified"
    finding["confidence"] = "limited"
    finding["coverage"] = "partial"
    finding["uncertainty"] = ""
    context["document"] = document


@given("a merged delivery claim without merge evidence")
def unsupported_delivery(context):
    document = verified_example()
    document["findings"][0]["delivery_claims"] = [
        {"state": "merged", "evidence_ids": ["validation-command"]}
    ]
    context["document"] = document


@when("the marketplace contract is validated")
def validate_catalog(context):
    context["action"]()
    context["accepted"] = True


@when("the finding contract is validated")
def validate_finding(context):
    try:
        validate_finding_document(context["document"], "test-finding")
    except ValidationError as error:
        context["error"] = str(error)
    else:
        context["accepted"] = True


@then("every package is categorized and indexed for each supported host")
def catalog_accepted(context):
    assert context["accepted"] is True


@then("the finding is accepted")
def finding_accepted(context):
    assert context["accepted"] is True


@then(parsers.parse("the finding is rejected for {reason}"))
def finding_rejected(context, reason):
    assert "error" in context
    expected = {
        "missing uncertainty": "requires a plain-language uncertainty statement",
        "missing delivery evidence": "missing evidence for delivery state merged",
    }
    assert expected[reason] in context["error"]


def test_verified_high_confidence_rejects_stale_evidence():
    document = copy.deepcopy(verified_example())
    document["findings"][0]["evidence"][0]["freshness"] = "stale"
    document["findings"][0]["uncertainty"] = "The evidence is stale."
    with pytest.raises(ValidationError, match="require current evidence"):
        validate_finding_document(document, "test-finding")
