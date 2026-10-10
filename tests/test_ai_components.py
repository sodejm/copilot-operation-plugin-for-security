"""Acceptance tests for the offline AI component verifier."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from cops.evidence.ai_components import (
    ComponentVerificationError,
    assess_component_baselines,
    canonical_component_identity,
    validate_component_manifest,
    verify_component_manifest,
)
from cops.evidence.ai_inventory import import_inventory

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def manifest():
    return {
        "schema_version": "cops.ai-components/v1",
        "manifest_id": "review-1",
        "policy": {"version": "policy-1", "signing_required": True},
        "components": [
            {
                "component_id": "billing-tool",
                "component_type": "mcp_tool",
                "source": {"provider": "internal", "name": "billing"},
                "version": "1.0.0",
                "expected_publisher": "security",
                "provenance_evidence_refs": ["S01"],
                "licensing_decision_id": "COPS-DECISION-REFERENCE-ONLY",
                "dependencies": [],
                "inventory_asset_id": "langsmith/tenant-fixture/tool/billing",
                "behavior": {
                    "name": "billing",
                    "description": "Read ledger entries.",
                    "input_schema": {"type": "object", "properties": {"id": {"type": "string"}}},
                    "policy": {"read_only": True},
                },
                "signature": {"status": "verified", "receipt_id": "receipt-billing"},
                "organizational_approval": {"status": "approved"},
            },
            {
                "component_id": "support-prompt",
                "component_type": "prompt_bundle",
                "source": {"provider": "internal", "name": "support"},
                "version": "1.0.0",
                "expected_publisher": "security",
                "provenance_evidence_refs": ["S01"],
                "licensing_decision_id": "COPS-DECISION-REFERENCE-ONLY",
                "dependencies": ["billing-tool"],
                "behavior": {"content_digest": "a" * 64},
                "signature": {"status": "verified", "receipt_id": "receipt-support"},
                "organizational_approval": {"status": "approved"},
            },
        ],
    }


def snapshot():
    fixture = FIXTURES / "ai_inventory_v1.json"
    return import_inventory(json.loads(fixture.read_text()), engagement_id="engagement-a")


def test_versioned_component_schema_validates_fixture_and_rejects_unknown_fields():
    schema = json.loads((ROOT / "cops/evidence/schemas/ai-components-v1.schema.json").read_text())
    fixture = json.loads((FIXTURES / "ai_components_v1.json").read_text())
    validator = Draft202012Validator(schema)
    validator.validate(fixture)
    assert validate_component_manifest(fixture)["manifest_id"] == "review-1"
    invalid = deepcopy(fixture)
    invalid["unrecognized"] = True
    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_canonical_identity_detects_schema_description_and_bundle_substitution():
    first = manifest()
    reordered = deepcopy(first["components"][0])
    reordered["behavior"]["input_schema"] = {"properties": {"id": {"type": "string"}}, "type": "object"}
    assert canonical_component_identity(first["components"][0]) == canonical_component_identity(reordered)
    altered = deepcopy(first)
    altered["components"][0]["behavior"]["description"] = "Transfer ledger entries."
    assert canonical_component_identity(first["components"][0]) != canonical_component_identity(
        altered["components"][0]
    )
    altered["components"][0]["behavior"]["input_schema"]["properties"]["limit"] = {"type": "integer"}
    assert canonical_component_identity(first["components"][0]) != canonical_component_identity(
        altered["components"][0]
    )
    altered["components"][1]["behavior"]["content_digest"] = "b" * 64
    assert canonical_component_identity(first["components"][1]) != canonical_component_identity(
        altered["components"][1]
    )


def test_observation_binds_identity_and_reports_substitution_without_execution():
    normalized = validate_component_manifest(manifest(), inventory=snapshot(), engagement_id="engagement-a")
    report = verify_component_manifest(
        manifest(),
        inventory=snapshot(),
        engagement_id="engagement-a",
        observations=[{"component_id": "billing-tool", "manifest_id": "review-1", "identity": "substituted"}],
    )
    result = report["components"][0]
    assert normalized["components"][0]["identity"] != "substituted"
    assert result["integrity"] == "substituted"
    assert result["outcome"] == "rejected"
    stale = verify_component_manifest(
        manifest(),
        inventory=snapshot(),
        engagement_id="engagement-a",
        observations=[
            {
                "component_id": "billing-tool",
                "manifest_id": "review-0",
                "identity": normalized["components"][0]["identity"],
            }
        ],
    )
    assert stale["components"][0]["integrity"] == "stale_manifest"
    assert stale["components"][0]["outcome"] == "rejected"


@pytest.mark.parametrize(
    ("signature", "revoked", "expected"),
    [
        ("unsigned_allowed", [], "unsigned_allowed"),
        ("failed", [], "signature_failure"),
        ("untrusted", [], "untrusted_signer"),
        ("unsupported", [], "unsupported_verification"),
        ("verified", ["S01"], "revoked_evidence"),
    ],
)
def test_assurance_states_remain_distinct(signature, revoked, expected):
    document = manifest()
    document["components"][0]["signature"]["status"] = signature
    report = verify_component_manifest(document, revoked_evidence_ids=revoked)
    result = report["components"][0]
    assert expected in {result["authenticity"], result["provenance"]}


def test_verified_signature_claim_requires_a_matching_trusted_receipt():
    document = manifest()
    unverified = verify_component_manifest(document)["components"][0]
    assert unverified["authenticity"] == "unverified_signature_claim"
    assert unverified["outcome"] == "rejected"
    document["policy"]["signing_required"] = False
    optional = verify_component_manifest(document)["components"][0]
    assert optional["outcome"] == "limited"
    document["policy"]["signing_required"] = True
    identity = validate_component_manifest(document)["components"][0]["identity"]
    verified = verify_component_manifest(
        document,
        trusted_verification_receipts=[
            {
                "receipt_id": "receipt-billing",
                "component_id": "billing-tool",
                "identity": identity,
                "verifier": "offline-test",
            }
        ],
    )["components"][0]
    assert verified["authenticity"] == "verified"


def test_verified_outcome_requires_matching_component_observation():
    document = manifest()
    identity = validate_component_manifest(document)["components"][0]["identity"]
    receipts = [
        {
            "receipt_id": "receipt-billing",
            "component_id": "billing-tool",
            "identity": identity,
            "verifier": "offline-test",
        }
    ]
    unobserved = verify_component_manifest(document, trusted_verification_receipts=receipts)["components"][0]
    assert unobserved["integrity"] == "not_observed"
    assert unobserved["outcome"] == "limited"
    observed = verify_component_manifest(
        document,
        trusted_verification_receipts=receipts,
        observations=[
            {
                "component_id": "billing-tool",
                "manifest_id": "review-1",
                "identity": identity,
            }
        ],
    )["components"][0]
    assert observed["integrity"] == "match"
    assert observed["outcome"] == "verified"


def test_signing_required_rejects_unsupported_and_unsigned_states():
    for status in ("unsupported", "unsigned_allowed", "missing"):
        document = manifest()
        document["components"][0]["signature"] = {"status": status}
        result = verify_component_manifest(document)["components"][0]
        assert result["outcome"] == "rejected"
    document = manifest()
    document["policy"]["signing_required"] = False
    document["components"][0]["signature"] = {"status": "unsigned_allowed"}
    assert verify_component_manifest(document)["components"][0]["outcome"] == "limited"


def test_manifest_requires_a_registered_licensing_decision_and_reports_it():
    document = manifest()
    document["components"][0]["licensing_decision_id"] = "unknown-decision"
    with pytest.raises(ComponentVerificationError, match="missing_licensing_decision"):
        validate_component_manifest(document)
    result = verify_component_manifest(manifest())["components"][0]
    assert result["licensing_decision"]["decision_id"] == "COPS-DECISION-REFERENCE-ONLY"
    assert result["licensing_decision"]["rationale"]


def test_opaque_alias_has_limited_assurance_without_invented_digest():
    document = manifest()
    document["policy"]["signing_required"] = False
    document["components"] = [
        {
            "component_id": "latest-model",
            "component_type": "model_alias",
            "source": {"provider": "vendor", "name": "model"},
            "version": "latest",
            "expected_publisher": "vendor",
            "provenance_evidence_refs": ["S01"],
            "licensing_decision_id": "COPS-DECISION-REFERENCE-ONLY",
            "dependencies": [],
            "behavior": {"alias": "vendor/latest", "immutable_digest": None},
            "signature": {"status": "unsigned_allowed"},
            "organizational_approval": {"status": "approved"},
        }
    ]
    result = verify_component_manifest(document)["components"][0]
    assert result["integrity"] == "limited_opaque_alias"
    assert result["outcome"] == "limited"


def test_unknown_provenance_and_missing_inventory_component_are_rejected():
    document = manifest()
    document["components"][0]["provenance_evidence_refs"] = ["not-registered"]
    assert verify_component_manifest(document)["components"][0]["provenance"] == "missing_provenance"
    document = manifest()
    document["components"][0]["inventory_asset_id"] = "langsmith/tenant-fixture/missing"
    with pytest.raises(ComponentVerificationError, match="component_absent_from_inventory"):
        validate_component_manifest(document, inventory=snapshot(), engagement_id="engagement-a")
    with pytest.raises(ComponentVerificationError, match="inventory_engagement_required"):
        validate_component_manifest(manifest(), inventory=snapshot())


def test_baseline_stays_stale_after_component_is_restored():
    normalized = validate_component_manifest(manifest())
    original = normalized["components"][0]["identity"]
    changed = manifest()
    changed["components"][0]["behavior"]["description"] = "Changed behavior."
    baseline = {
        "baseline_id": "assessment-1",
        "reviewed_identities": {"billing-tool": original},
        "state": "current",
        "component_test_dependencies": {"test-billing": ["billing-tool"]},
        "component_assessment_scope": {"billing-tool": ["billing-assessment"]},
    }
    stale = assess_component_baselines(changed, [baseline])
    assert stale[0]["state"] == "stale"
    assert stale[0]["affected_tests"] == ["test-billing"]
    assert stale[0]["affected_assessment_scope"] == ["billing-assessment"]
    baseline["state"] = "stale"
    restored = assess_component_baselines(manifest(), [baseline])
    assert restored[0]["state"] == "stale"
    assert restored[0]["review_required"] and restored[0]["retest_required"]
