from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cops.evidence.canonical import canonical, digest
from cops.workflows.contracts import WorkflowContractError
from cops.workflows.playback import (
    DEFAULT_CATALOG_DIR,
    DEFAULT_SCENARIO_REGISTRY,
    DEFAULT_SPECIALIST_REGISTRY,
    EvidenceBundleSigner,
    IntegratedWorkflowError,
    load_integrated_workflows,
    run_fixture_profile,
    run_offline_playback,
    validate_integrated_workflow_catalog,
)


EXPECTED_PROFILES = {
    ("leaked-credential-blast-radius", "vulnerable"): "action_required",
    ("leaked-credential-blast-radius", "corrected"): "no_active_exposure_observed",
    ("cve-reachability-triage", "vulnerable"): "urgent_remediation",
    ("cve-reachability-triage", "corrected"): "known_corrected_component",
    ("cve-reachability-triage", "limited"): "insufficient_evidence",
    ("kubernetes-compromise-containment", "vulnerable"): "insufficient_lab_validation",
    ("kubernetes-compromise-containment", "corrected"): "no_containment_required",
    ("illicit-consent-remediation", "vulnerable"): "insufficient_lab_validation",
    ("illicit-consent-remediation", "corrected"): "no_suspicious_consent_observed",
    ("illicit-consent-remediation", "limited"): "insufficient_evidence",
    ("detection-rule-ci-validation", "verified"): "verified_detection",
    ("detection-rule-ci-validation", "detection_gap"): "detection_gap",
    ("pre-release-exposure-audit", "vulnerable"): "action_required",
    ("pre-release-exposure-audit", "corrected"): "no_exposure_observed",
    ("pre-release-exposure-audit", "limited"): "insufficient_evidence",
}

EXPECTED_SCENARIOS = {
    "leaked-credential-blast-radius": "COPS-E06.03-S01",
    "cve-reachability-triage": "COPS-E03.02-S01",
    "kubernetes-compromise-containment": "COPS-E10.08-S01",
    "illicit-consent-remediation": "COPS-E03.02-S01",
    "detection-rule-ci-validation": "COPS-E15.03-S01",
    "pre-release-exposure-audit": "COPS-E04.01-S01",
}


def _catalog_copy(tmp_path: Path) -> Path:
    target = tmp_path / "workflows"
    shutil.copytree(DEFAULT_CATALOG_DIR, target)
    return target


def test_catalog_contains_six_strict_versioned_workflows() -> None:
    catalog = validate_integrated_workflow_catalog()
    definitions = load_integrated_workflows()

    assert catalog["schema_version"] == "cops.integrated-workflow-catalog/v1"
    assert set(definitions) == {workflow_id for workflow_id, _ in EXPECTED_PROFILES}
    assert all(
        definition.to_dict()["schema_version"] == "cops.workflow-definition/v1"
        for definition in definitions.values()
    )
    assert sum(len(entry["profiles"]) for entry in catalog["workflows"]) == len(EXPECTED_PROFILES)


def test_every_stage_uses_a_registered_specialist() -> None:
    registry = json.loads(DEFAULT_SPECIALIST_REGISTRY.read_text(encoding="utf-8"))
    registered = {specialist["id"] for specialist in registry["specialists"]}

    for definition in load_integrated_workflows().values():
        assert {
            stage["action"]["specialist_id"] for stage in definition.stages
        } <= registered


def test_every_workflow_uses_a_registered_applicable_scenario() -> None:
    registry = json.loads(DEFAULT_SCENARIO_REGISTRY.read_text(encoding="utf-8"))
    registered = {scenario["scenario_id"] for scenario in registry["scenarios"]}

    definitions = load_integrated_workflows()
    assert {
        workflow_id: definition.scenario_id
        for workflow_id, definition in definitions.items()
    } == EXPECTED_SCENARIOS
    assert set(EXPECTED_SCENARIOS.values()) <= registered


@pytest.mark.parametrize(("workflow_id", "profile_id"), EXPECTED_PROFILES)
def test_all_fixture_profiles_compile_exact_plans_and_reach_declared_outcome(
    workflow_id: str, profile_id: str
) -> None:
    definition = load_integrated_workflows()[workflow_id]
    report = run_fixture_profile(workflow_id, profile_id)

    assert report["schema_version"] == "cops.integrated-workflow-playback/v1"
    assert report["status"] == "completed"
    assert report["outcome"] == EXPECTED_PROFILES[(workflow_id, profile_id)]
    assert len(report["stages"]) == len(definition.stages)
    for stage in definition.stages:
        state = report["stages"][stage["stage_id"]]
        plan = state["plan"]
        assert state["status"] == "success"
        assert len(state["evidence_refs"]) == 1
        assert plan["schema_version"] == "cops.action-plan/v1"
        assert plan["target"] == f"fixture://{workflow_id}"
        assert plan["operations"][0]["action"] == stage["action"]["action"]
        assert plan["operations"][0]["expected_evidence"]
        assert plan["operations"][0]["side_effects"] == []
        assert plan["limits"]["egress_allowed"] is False
        assert plan["operations"][0]["idempotent"] is True
        assert plan["plan_digest"]


def test_missing_reachability_never_claims_non_exploitability() -> None:
    report = run_fixture_profile("cve-reachability-triage", "limited")

    assessment = report["stages"]["reachability"]["outputs"]["reachability_assessment"]
    assert assessment["status"] == "not_established"
    assert assessment["evidence_present"] is False
    assert assessment["non_exploitability_established"] is False
    assert report["outputs"]["remediation"]["non_exploitability_established"] is False
    assert report["outcome"] == "insufficient_evidence"


def test_fixture_evidence_bundle_is_explicitly_unsigned_without_a_signer() -> None:
    report = run_fixture_profile("leaked-credential-blast-radius", "vulnerable")
    bundle = report["outputs"]["evidence_bundle"]

    assert bundle["signature"] == {
        "status": "unsigned",
        "algorithm": None,
        "key_id": None,
        "value": None,
        "payload_digest": digest(bundle["payload"]),
        "reason": "signer_not_configured",
    }
    assert bundle["cryptographically_signed"] is False
    assert bundle["signature_verified"] is False
    assert bundle["authenticity_established"] is False
    assert bundle["trust_status"] == "unsigned"
    assert bundle["live_signing_required"] is True


def test_fixture_evidence_bundle_can_be_cryptographically_signed() -> None:
    private_key = Ed25519PrivateKey.generate()
    report = run_fixture_profile(
        "leaked-credential-blast-radius",
        "vulnerable",
        evidence_signer=EvidenceBundleSigner("fixture-signing-key", private_key),
    )
    bundle = report["outputs"]["evidence_bundle"]
    signature = bundle["signature"]

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature["public_key"]))
    public_key.verify(bytes.fromhex(signature["value"]), canonical(bundle["payload"]))
    assert signature["status"] == "signed"
    assert signature["algorithm"] == "ed25519"
    assert signature["key_id"] == "fixture-signing-key"
    assert signature["payload_digest"] == digest(bundle["payload"])
    assert bundle["cryptographically_signed"] is True
    assert bundle["signature_verified"] is True
    assert bundle["authenticity_established"] is False
    assert bundle["trust_status"] == "caller_configured_unanchored"
    assert bundle["live_signing_required"] is False

    changed_payload = dict(bundle["payload"])
    changed_payload["checklist"] = []
    with pytest.raises(InvalidSignature):
        public_key.verify(bytes.fromhex(signature["value"]), canonical(changed_payload))


def test_kubernetes_playback_models_lab_expectations_without_claiming_activity() -> None:
    report = run_fixture_profile("kubernetes-compromise-containment", "vulnerable")
    application = report["stages"]["lab_apply"]["outputs"]["lab_application"]

    assert application["fixture_only"] is True
    assert application["activity_performed"] is False
    assert application["live_authorization_required"] is True
    assert application["modeled_changes"]
    assert application["validation_status"] == "insufficient_lab_validation"
    assert application["restoration_verified"] is False
    assert report["outcome"] == "insufficient_lab_validation"
    assert report["outputs"]["report"]["activity_performed"] is False
    assert report["outputs"]["report"]["connectivity_verified"] is False
    assert report["outputs"]["report"]["cleanup_verified"] is False
    assert report["outputs"]["report"]["requires_authorized_lab"] is True


def test_consent_playback_models_validation_without_claiming_package_execution() -> None:
    report = run_fixture_profile("illicit-consent-remediation", "vulnerable")
    validation = report["outputs"]["lab_validation"]

    assert report["outcome"] == "insufficient_lab_validation"
    assert validation["fixture_only"] is True
    assert validation["activity_performed"] is False
    assert validation["identity_package_exercised"] is False
    assert validation["hunt_package_exercised"] is False
    assert validation["requires_authorized_lab"] is True
    assert validation["modeled_expectations"]


def test_detection_playback_reports_attack_and_benign_counts() -> None:
    verified = run_fixture_profile("detection-rule-ci-validation", "verified")
    gap = run_fixture_profile("detection-rule-ci-validation", "detection_gap")

    assert verified["outputs"]["report"]["status"] == "verified_detection"
    assert verified["outputs"]["report"]["counts"] == {
        "attack_matches": 1,
        "benign_matches": 0,
    }
    assert gap["outputs"]["report"]["status"] == "detection_gap"
    assert gap["outputs"]["report"]["rule_proposal"]["sigma"]
    assert gap["outputs"]["report"]["rule_proposal"]["kql"]


def test_exposure_audit_drops_out_of_scope_inventory_and_routes() -> None:
    report = run_fixture_profile("pre-release-exposure-audit", "vulnerable")

    inventory = report["stages"]["inventory"]["outputs"]["scoped_inventory"]
    routes = report["stages"]["routes"]["outputs"]["route_assessment"]
    assert {item["host"] for item in inventory["records"]} == {"preview.example.test"}
    assert {item["host"] for item in routes["checks"]} == {"preview.example.test"}


def test_definition_tampering_is_detected_before_playback(tmp_path: Path) -> None:
    catalog_dir = _catalog_copy(tmp_path)
    definition_path = catalog_dir / "cve-reachability-triage.workflow.json"
    definition = json.loads(definition_path.read_text(encoding="utf-8"))
    definition["description"] = "tampered"
    definition_path.write_text(json.dumps(definition), encoding="utf-8")

    with pytest.raises(IntegratedWorkflowError, match="workflow_digest_mismatch"):
        validate_integrated_workflow_catalog(catalog_dir)


def test_catalog_rejects_unregistered_specialist_even_with_updated_digest(
    tmp_path: Path,
) -> None:
    catalog_dir = _catalog_copy(tmp_path)
    definition_path = catalog_dir / "cve-reachability-triage.workflow.json"
    definition = json.loads(definition_path.read_text(encoding="utf-8"))
    definition["stages"][0]["action"]["specialist_id"] = "unregistered-specialist"
    definition_path.write_text(json.dumps(definition), encoding="utf-8")
    catalog_path = catalog_dir / "catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    entry = next(
        item
        for item in catalog["workflows"]
        if item["workflow_id"] == "cve-reachability-triage"
    )
    entry["definition_digest"] = digest(definition)
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    with pytest.raises(IntegratedWorkflowError, match="unregistered_specialist"):
        validate_integrated_workflow_catalog(catalog_dir)


def test_catalog_rejects_unregistered_scenario_even_with_updated_digest(
    tmp_path: Path,
) -> None:
    catalog_dir = _catalog_copy(tmp_path)
    definition_path = catalog_dir / "cve-reachability-triage.workflow.json"
    definition = json.loads(definition_path.read_text(encoding="utf-8"))
    definition["scenario_id"] = "COPS-E99.99-S99"
    definition_path.write_text(json.dumps(definition), encoding="utf-8")
    catalog_path = catalog_dir / "catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    entry = next(
        item
        for item in catalog["workflows"]
        if item["workflow_id"] == "cve-reachability-triage"
    )
    entry["definition_digest"] = digest(definition)
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    with pytest.raises(IntegratedWorkflowError, match="unregistered_scenario"):
        validate_integrated_workflow_catalog(catalog_dir)


def test_fixture_tampering_is_detected_before_playback(tmp_path: Path) -> None:
    catalog_dir = _catalog_copy(tmp_path)
    fixture_path = catalog_dir / "fixtures" / "cve-reachability-triage.limited.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture["inputs"]["callgraph_evidence"] = {"paths": [{"reachable": True}]}
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    with pytest.raises(IntegratedWorkflowError, match="fixture_digest_mismatch"):
        validate_integrated_workflow_catalog(catalog_dir)


def test_catalog_rejects_path_traversal(tmp_path: Path) -> None:
    catalog_dir = _catalog_copy(tmp_path)
    catalog_path = catalog_dir / "catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["workflows"][0]["path"] = "../outside.json"
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    with pytest.raises(IntegratedWorkflowError, match="unsafe_catalog_path"):
        validate_integrated_workflow_catalog(catalog_dir)


def test_playback_rejects_invalid_typed_inputs() -> None:
    fixture = json.loads(
        (DEFAULT_CATALOG_DIR / "fixtures" / "cve-reachability-triage.limited.json").read_text(
            encoding="utf-8"
        )
    )
    inputs = dict(fixture["inputs"])
    inputs["advisory"] = "not-an-object"

    with pytest.raises(WorkflowContractError, match="workflow_input_type"):
        run_offline_playback("cve-reachability-triage", inputs)


@pytest.mark.parametrize(
    ("workflow_id", "profile_id", "code"),
    [
        ("unknown-workflow", "vulnerable", "unknown_workflow"),
        ("cve-reachability-triage", "unknown-profile", "unknown_fixture_profile"),
    ],
)
def test_unknown_workflow_or_profile_is_rejected(workflow_id: str, profile_id: str, code: str) -> None:
    with pytest.raises(IntegratedWorkflowError, match=code):
        run_fixture_profile(workflow_id, profile_id)
