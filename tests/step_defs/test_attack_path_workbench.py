"""Executable acceptance scenarios for the illustrative offline workbench."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins/detection-hunting/attack-path-workbench"
FIXTURE = PLUGIN / "fixtures/illustrative"
sys.path.insert(0, str(PLUGIN))
from attackpath.azure import report as azure_report  # noqa: E402
from attackpath.azure.model import AzureError  # noqa: E402
from attackpath.core import (  # noqa: E402
    GateError,
    analyze,
    audit_report,
    canonical,
    collect_reviews,
    file_hash,
    query_intent,
    validate_input,
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
    assert all(
        f["source"]["record_pointer"].startswith("/records/")
        and f["source"]["file_sha256"] == file_hash(context["export"])
        for f in report["evidence"]
    )
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
    assert all(
        path["premise"] == "conditional_successful_exploitation_of_finding"
        for path in report["supported_paths"] + report["candidate_paths"]
    )


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
    assert all(
        action["owner"] is None and action["closure_evidence"] is None for action in context["report"]["actions"]
    )


@given("two conflicting structured specialist opinions")
def conflicting_reviews(context):
    report = analyze(context["input"])
    evidence = report["supported_paths"][0]["evidence_refs"]
    packet_hash = hashlib.sha256(canonical(report["supported_paths"][0])).hexdigest()
    common = {
        "schema_version": "attackpath.review/v1",
        "specialist": "path_skeptic",
        "prompt_version": "illustrative/v1",
        "input_sha256": packet_hash,
        "model_settings": None,
        "evidence_refs": evidence,
        "alternatives": [],
        "validation_questions": ["Confirm the transition"],
        "disagrees_with_gate": False,
        "human_disposition": None,
    }
    context["report"] = report
    context["reviews"] = [
        {**common, "verdict": "supported", "rationale": "Illustrative structural support only"},
        {
            **common,
            "verdict": "candidate",
            "rationale": "Illustrative precondition disputed",
            "disagrees_with_gate": True,
        },
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


@given("an illustrative manifest with an oversized source or unsafe path")
def bounded_input(context):
    context["source_size"] = context["export"].stat().st_size
    (context["input"].parent / "linked-export.json").symlink_to(context["export"])


@when("the export is analyzed")
def analyze_bounded_input(context):
    context["valid_report"] = analyze(context["input"])
    with pytest.raises(GateError, match="file_limit") as oversized:
        analyze(context["input"], {"file_bytes": context["source_size"] - 1})
    context["oversized_error"] = oversized.value
    manifest = json.loads(context["input"].read_text())
    manifest["sources"][0]["path"] = "linked-export.json"
    context["input"].write_bytes(canonical(manifest))
    with pytest.raises(GateError, match="unsafe_file") as linked:
        analyze(context["input"])
    context["linked_error"] = linked.value


@then("ingestion rejects the input before report completion")
def bounded_input_rejected(context):
    assert str(context["oversized_error"]) == "file_limit"
    assert str(context["linked_error"]) == "unsafe_file"


@then("successful runs record effective limits and consumed budget")
def ingestion_receipt(context):
    report = context["valid_report"]
    receipt = report["ingestion"]
    assert receipt["run_id"] == report["run"]["run_id"]
    assert receipt["files"] == 2
    assert receipt["bytes"] >= context["input"].stat().st_size + context["source_size"]
    assert receipt["bytes"] <= receipt["limits"]["total_bytes"]


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


@given("an illustrative graph with more routes than the chosen search budget")
def bounded_search_graph(context):
    context["search_limits"] = {"expansions": 1}


@when("analysis reaches an expansion, frontier, path, or report byte limit")
def analyze_with_search_limits(context):
    context["report"] = analyze(context["input"], search_limits=context["search_limits"])


@then("the v2 report records the effective limits, consumption, and stop reason")
def report_v2_search_receipt(context):
    report = context["report"]
    assert report["schema_version"] == "attackpath.report/v2"
    assert report["search"]["stop_reason"] == "expansion_limit"
    assert report["search"]["consumed"]["expansions"] == 1
    assert not report["search"]["complete"]


@then("incomplete rankings are labelled as best discovered routes")
def incomplete_ranking_label(context):
    assert context["report"]["search"]["ranking_scope"] == "best_discovered"


@then("the same policy and receipt replay during claim audit")
def replay_search_policy_audit(context):
    report = context["report"]
    manifest = json.loads(context["input"].read_text())
    _, sources = validate_input(manifest, context["input"].parent)
    audit_report(report, sources)
    tampered = copy.deepcopy(report)
    tampered["search"]["consumed"]["expansions"] += 1
    with pytest.raises(GateError, match="search receipt"):
        audit_report(tampered, sources)


@given("the four legacy reports target a fresh descriptor-anchored directory")
def fresh_legacy_report_set(context):
    reports = {
        "report.json": b'{"report":true}\n',
        "graph.json": b'{"graph":true}\n',
        "report.md": b"# Report\n",
        "remediation-ledger.json": b'{"actions":[]}\n',
    }
    marker = {
        "schema_version": "attackpath.completion/v1",
        "run_id": "acceptance-run",
        "status": "complete",
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in reports.items()},
    }
    context["legacy_contents"] = {**reports, "completion.json": canonical(marker)}


@when("any report write fails or the requested output parent is swapped")
def interrupt_legacy_report_sets(context):
    contents = context["legacy_contents"]
    root = context["input"].parent
    partial = root / "partial-reports"
    real_open = os.open

    def fail_graph(path, flags, mode=0o777, *, dir_fd=None):
        if path == "graph.json":
            raise OSError(errno.ENOSPC, "injected report failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with (
        mock.patch.object(azure_report.os, "open", side_effect=fail_graph) as patched_open,
        mock.patch.object(azure_report.os, "supports_dir_fd", os.supports_dir_fd | {patched_open}),
    ):
        with pytest.raises(AzureError):
            azure_report.write_files(partial, contents, 4096)

    parent = root / "requested-parent"
    parent.mkdir()
    moved_parent = root / "held-parent"
    external = root / "replacement-parent"
    external.mkdir()
    swapped = False

    def swap_parent(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "report.json" and not swapped:
            swapped = True
            os.rename(parent, moved_parent)
            os.symlink(external, parent, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with (
        mock.patch.object(azure_report.os, "open", side_effect=swap_parent) as patched_open,
        mock.patch.object(azure_report.os, "supports_dir_fd", os.supports_dir_fd | {patched_open}),
    ):
        with pytest.raises(AzureError):
            azure_report.write_files(parent / "reports", contents, 4096)

    context["partial_output"] = partial
    context["swapped_output"] = moved_parent / "reports"


@then("no completion marker created by that invocation remains")
def interrupted_sets_have_no_completion(context):
    assert not (context["partial_output"] / "completion.json").exists()
    assert not (context["swapped_output"] / "completion.json").exists()


@then("successful runs bind all four exact report bytes in a last-written marker")
def successful_set_has_bound_completion(context):
    output = context["input"].parent / "complete-reports"
    azure_report.write_files(output, context["legacy_contents"], 4096)
    marker = json.loads((output / "completion.json").read_bytes())
    assert set(marker["files"]) == {
        "report.json",
        "graph.json",
        "report.md",
        "remediation-ledger.json",
    }
    for name, expected in marker["files"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected
