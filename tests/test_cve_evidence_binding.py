from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from cops.workflows.playback import _cve_controls, _cve_ingest, _cve_reachability, _cve_remediate


FIXTURES = Path(__file__).resolve().parents[1] / "catalog/workflows/fixtures"


def evaluate(inputs: dict) -> dict:
    values = copy.deepcopy(inputs)
    values.update(_cve_ingest(values))
    values.update(_cve_reachability(values))
    values.update(_cve_controls(values))
    values.update(_cve_remediate(values))
    return values


def inputs() -> dict:
    return json.loads((FIXTURES / "cve-reachability-triage.vulnerable.json").read_text())["inputs"]


def test_unrelated_loaded_module_cannot_establish_reachability() -> None:
    values = inputs()
    values["callgraph_evidence"] = {"paths": []}
    values["runtime_evidence"] = {"modules": [{"name": "unrelated", "loaded": True}]}
    result = evaluate(values)
    assert result["reachability_assessment"]["status"] == "not_established"
    assert result["outcome"] == "insufficient_evidence"


@pytest.mark.parametrize("field,value", [("name", "unrelated"), ("version", "99.0.0"), ("source_sha256", "0" * 64), ("ecosystem", "unknown")])
def test_runtime_component_mismatch_is_insufficient(field: str, value: str) -> None:
    values = inputs()
    values["callgraph_evidence"] = {}
    values["runtime_evidence"]["modules"][0]["component"][field] = value
    result = evaluate(values)
    assert result["outcome"] == "insufficient_evidence"
    assert result["reachability_assessment"]["non_exploitability_established"] is False


@pytest.mark.parametrize("patch", [{"calls": 0}, {"calls": True}, {"execution_id": ""}, {"observed_at": "bad"}, {"evidence_ref": ""}])
def test_runtime_record_requires_actual_invocation_and_provenance(patch: dict) -> None:
    values = inputs()
    values["callgraph_evidence"] = {}
    values["runtime_evidence"]["modules"][0].update(patch)
    assert evaluate(values)["outcome"] == "insufficient_evidence"


@pytest.mark.parametrize("inventory", [{}, {"complete": False, "packages": []}, {"complete": True, "packages": [None]}, {"complete": True, "packages": "invalid"}])
def test_incomplete_inventory_cannot_establish_reachability(inventory: dict) -> None:
    values = inputs()
    values["dependency_inventory"] = inventory
    assert evaluate(values)["outcome"] == "insufficient_evidence"


def test_unbound_control_does_not_lower_priority() -> None:
    values = inputs()
    values["compensating_controls"] = {"controls": [{"verified": True, "name": "WAF"}]}
    result = evaluate(values)
    assert result["outcome"] == "urgent_remediation"
    assert result["control_assessment"]["count"] == 0


@pytest.mark.parametrize("malformed", [None, {}, {"name": "unrelated"}])
def test_valid_component_cannot_mask_malformed_inventory(malformed: object) -> None:
    values = inputs()
    values["dependency_inventory"]["packages"].append(malformed)
    assert evaluate(values)["outcome"] == "insufficient_evidence"


def test_malformed_advisory_component_prevents_resolution() -> None:
    values = inputs()
    values["advisory"]["components"].append(None)
    assert evaluate(values)["outcome"] == "insufficient_evidence"


def test_empty_and_negative_reachability_never_proves_non_exploitability() -> None:
    values = inputs()
    values["runtime_evidence"] = {"modules": []}
    values["callgraph_evidence"] = {"paths": []}
    result = evaluate(values)
    assert result["outcome"] == "insufficient_evidence"
    assert result["reachability_assessment"]["evidence_present"] is False
    assert result["remediation"]["non_exploitability_established"] is False


def test_corrected_component_has_distinct_evidence_backed_outcome() -> None:
    values = json.loads((FIXTURES / "cve-reachability-triage.corrected.json").read_text())["inputs"]
    result = evaluate(values)
    assert result["outcome"] == "known_corrected_component"
    assert result["reachability_assessment"]["non_exploitability_established"] is False


def test_bound_negative_callgraph_is_observation_not_a_safety_claim() -> None:
    values = inputs()
    record = values["runtime_evidence"]["modules"].pop()
    record.pop("calls")
    record["reachable"] = False
    values["callgraph_evidence"] = {"paths": [record]}
    result = evaluate(values)
    assert result["outcome"] == "prioritized_remediation"
    assert result["reachability_assessment"]["non_exploitability_established"] is False
    record["reachable"] = True
    assert evaluate(values)["outcome"] == "urgent_remediation"


def test_only_component_and_advisory_bound_controls_are_counted() -> None:
    values = inputs()
    control = {**values["runtime_evidence"]["modules"][0], "verified": True,
               "advisory_id": values["advisory"]["id"], "name": "synthetic filter"}
    values["compensating_controls"] = {"controls": [control]}
    assert evaluate(values)["control_assessment"]["count"] == 1
    control["advisory_id"] = "unrelated-advisory"
    assert evaluate(values)["control_assessment"]["count"] == 0


def test_pinned_advisory_matches_reviewed_service_source() -> None:
    from cops.laboratory.service_boundaries import query_component

    values = inputs()
    for profile in ("vulnerable", "corrected"):
        values["dependency_inventory"] = {"complete": True, "packages": [query_component(profile)]}
        assert evaluate(values)["dependency_match"]["resolved"] is True


def test_laboratory_advisory_matches_offline_fixture_and_manifest() -> None:
    from cops.laboratory.service_lab import FIXTURE_DIRECTORY, verify_fixture_manifest

    verify_fixture_manifest()
    assert json.loads((FIXTURE_DIRECTORY / "cve-advisory.json").read_text()) == inputs()["advisory"]
