"""Executable acceptance scenarios for the illustrative offline workbench."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest
from pytest_bdd import given, scenarios, then, when


ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins/detection-hunting/attack-path-workbench"
FIXTURE = PLUGIN / "fixtures/illustrative"
sys.path.insert(0, str(PLUGIN))
from attackpath.core import (  # noqa: E402
    GateError, analyze, audit_report, canonical, collect_reviews, file_hash,
    query_intent, validate_input,
)


scenarios("../../specs/features/attack_path_workbench.feature")


@pytest.fixture
def context(tmp_path):
    for name in ("input.json", "export.json"):
        (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())
    return {"input": tmp_path / "input.json", "export": tmp_path / "export.json"}


def change_export(context, change):
    export_path = context["export"]
    export = json.loads(export_path.read_text())
    change(export)
    export_path.write_bytes(canonical(export))
    input_path = context["input"]
    manifest = json.loads(input_path.read_text())
    manifest["sources"][0]["sha256"] = file_hash(export_path)
    manifest["sources"][0]["record_count"] = len(export["records"])
    input_path.write_bytes(canonical(manifest))


@given("an illustrative local export and versioned input")
def valid_input(context):
    assert context["input"].is_file() and context["export"].is_file()


@when("the source hash differs from the declared hash")
def altered_source(context):
    context["export"].write_bytes(context["export"].read_bytes() + b"\n")


@then("analysis stops with an input gate error")
def bad_hash_stops(context):
    with pytest.raises(GateError, match="SHA-256 mismatch"):
        analyze(context["input"])


@given("accepted and malformed illustrative records")
def mixed_records(context):
    assert json.loads(context["export"].read_text())["records"][-1]["record_type"] == "undocumented"


@when("the export is normalized")
def normalized(context):
    context["report"] = analyze(context["input"])


@then("each accepted fact has a source pointer and malformed records are quarantined")
def provenance_reconciles(context):
    report = context["report"]
    assert all(f["source"]["record_pointer"].startswith("/records/") and
               f["source"]["file_sha256"] == file_hash(context["export"]) for f in report["evidence"])
    assert any("unknown record type" in item["reason"] for item in report["quarantine"])
    counts = report["reconciliation"]
    assert counts["raw"] == counts["accepted"] + counts["quarantined"] + counts["rejected"]


@given("an edge with a missing node or prerequisite")
def invalid_edge(context):
    records = json.loads(context["export"].read_text())["records"]
    assert any(row.get("id") == "ILL-BROKEN" for row in records)
    assert any(row.get("id") == "ILL-HYPOTHETICAL" for row in records)


@when("the graph is constructed")
def constructed(context):
    context["report"] = analyze(context["input"])


@then("the invalid transition is excluded with a gate reason")
def invalid_edge_excluded(context):
    report = context["report"]
    assert any("edge endpoint missing" in item["reason"] for item in report["graph_exclusions"])
    assert all(edge["edge_id"] != "ILL-BROKEN" for edge in report["graph"]["edges"])
    assert report["gate_results"]["G3"] == "warning_excluded"


@given("observed and hypothetical conditional transitions")
def observed_and_hypothetical(context):
    records = json.loads(context["export"].read_text())["records"]
    assert {row["support"] for row in records if row.get("record_type") == "edge"} == {"observed", "hypothesis"}


@when("paths are traced to a user-defined crown jewel")
def traced(context):
    context["report"] = analyze(context["input"])


@then("supported structural routes and candidate routes are separate")
def separated(context):
    report = context["report"]
    assert len(report["supported_paths"]) == len(report["candidate_paths"]) == 1
    assert not report["supported_paths"][0]["gaps"]
    assert any("missing capability control" in gap for gap in report["candidate_paths"][0]["gaps"])
    assert all(path["premise"] == "conditional_successful_exploitation_of_finding"
               for path in report["supported_paths"] + report["candidate_paths"])


@given("duplicate routes and supported assets")
def duplicate_routes(context):
    def add_duplicate(export):
        duplicate = copy.deepcopy(next(row for row in export["records"] if row.get("id") == "ILL-PERMISSION"))
        duplicate["id"] = "ILL-PERMISSION-SECOND"
        export["records"].append(duplicate)
    change_export(context, add_duplicate)


@when("paths are ranked")
def ranked(context):
    context["report"] = analyze(context["input"])


@then("equivalent routes are grouped and distinct supported assets are counted once")
def grouped(context):
    supported = context["report"]["supported_paths"]
    assert len(supported) == 1
    path = supported[0]
    assert path["blast_radius"]["evidenced_asset_count"] == 3
    assert len(set(path["blast_radius"]["evidenced_asset_ids"])) == 3
    assert len(path["steps"][-1]["supporting_evidence_refs"]) == 2


@given("a path without an approved impact profile")
def no_impact_profile(context):
    assert json.loads(context["input"].read_text())["context"]["impact_profile_id"] is None


@when("consequences are assessed")
def assessed(context):
    context["report"] = analyze(context["input"])


@then("potential CIA effects are conditional and business rating is unrated")
def unrated(context):
    path = context["report"]["supported_paths"][0]
    assert path["impact"]["potential_cia"] == ["confidentiality"]
    assert path["impact"]["business_rating"] == "unrated"
    assert path["premise"] == "conditional_successful_exploitation_of_finding"


@given("no approved Wiz documentation or MITRE reference bundle")
def no_references(context):
    assert not json.loads(context["input"].read_text()).get("reference_bundle")


@when("query and behavior output is requested")
def request_integrations(context):
    context["intent"] = query_intent("ILL-FINDING", "ILL-CROWN", "ILL-SCOPE")
    context["report"] = analyze(context["input"])


@then("query rendering is blocked and technique and flow outputs remain pending")
def integrations_pending(context):
    assert context["intent"]["render_status"] == "blocked_pending_docs"
    assert context["report"]["technique_mappings"] == []
    assert context["report"]["attack_flow"]["status"] == "pending_reference_bundle"


@given("a report with cited material claims")
def cited_report(context):
    context["report"] = analyze(context["input"])
    _, sources = validate_input(json.loads(context["input"].read_text()), context["input"].parent)
    audit_report(context["report"], sources)


@when("identical inputs are analyzed twice")
def repeat_analysis(context):
    context["repeat"] = analyze(context["input"])


@then("canonical outputs match and the ledger has no invented owner or closure")
def reproducible(context):
    assert canonical(context["report"]) == canonical(context["repeat"])
    assert all(action["owner"] is None and action["closure_evidence"] is None
               for action in context["report"]["actions"])


@given("two conflicting structured specialist opinions")
def conflicting_reviews(context):
    report = analyze(context["input"])
    evidence = report["supported_paths"][0]["evidence_refs"]
    packet_hash = hashlib.sha256(canonical(report["supported_paths"][0])).hexdigest()
    common = {"schema_version": "attackpath.review/v1", "specialist": "path_skeptic",
              "prompt_version": "illustrative/v1", "input_sha256": packet_hash, "model_settings": None,
              "evidence_refs": evidence, "alternatives": [], "validation_questions": ["Confirm the transition"],
              "disagrees_with_gate": False, "human_disposition": None}
    context["report"] = report
    context["reviews"] = [
        {**common, "verdict": "supported", "rationale": "Illustrative structural support only"},
        {**common, "verdict": "candidate", "rationale": "Illustrative precondition disputed",
         "disagrees_with_gate": True},
    ]


@when("reviews are collected")
def collect(context):
    context["reviewed"] = collect_reviews(context["report"], context["reviews"])


@then("both opinions remain visible for human disposition")
def keep_disagreement(context):
    reviewed = context["reviewed"]
    assert {item["verdict"] for item in reviewed["human_review"]} == {"supported", "candidate"}
    assert all(item["human_disposition"] is None for item in reviewed["human_review"])
    assert reviewed["supported_paths"] == context["report"]["supported_paths"]
    assert reviewed["gate_results"] == context["report"]["gate_results"]
    _, sources = validate_input(json.loads(context["input"].read_text()), context["input"].parent)
    audit_report(reviewed, sources)


@given("a broken illustrative export")
def broken_export(context):
    context["export"].write_bytes(context["export"].read_bytes() + b"\n")


@when("the source is corrected and reanalyzed")
def correction(context):
    with pytest.raises(GateError, match="SHA-256 mismatch"):
        analyze(context["input"])
    context["export"].write_bytes((FIXTURE / "export.json").read_bytes())
    context["report"] = analyze(context["input"])


@then("the corrected input succeeds without reusing the failed result")
def recovered(context):
    assert context["report"]["gate_results"]["G1"] == "pass"
    assert len(context["report"]["supported_paths"]) == 1
