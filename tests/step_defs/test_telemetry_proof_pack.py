"""Executable acceptance scenarios for offline telemetry proof correlation."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins/logging-telemetry/telemetry-proof-pack"
if str(PLUGIN) not in sys.path:
    sys.path.insert(0, str(PLUGIN))

from proofpack.cli import load_evidence_files  # noqa: E402
from proofpack.correlator import correlate_pipeline_evidence  # noqa: E402
from proofpack.models import RunManifest  # noqa: E402
from proofpack.reporting import render_markdown_report  # noqa: E402

scenarios("../../specs/features/telemetry_proof_pack.feature")

EVIDENCE_TIMESTAMPS = {
    "source_event": "timestamp",
    "cribl_route": "timestamp",
    "destination_indexing": "indexed_time",
    "query_evaluation": "evaluation_time",
    "alert_creation": "created_time",
}
STAGE_NAMES = {
    "source_event": "source_emission",
    "cribl_route": "pipeline_routing",
    "destination_indexing": "destination_indexing",
    "query_evaluation": "query_evaluation",
    "alert_creation": "alert_creation",
}


@pytest.fixture
def context() -> dict[str, object]:
    return {}


def _load_case(context: dict[str, object], path: str) -> None:
    directory = PLUGIN / "fixtures" / path
    context["manifest"] = RunManifest.from_dict(json.loads((directory / "manifest.json").read_text(encoding="utf-8")))
    context["evidence"] = load_evidence_files(directory)


def _within_window(context: dict[str, object], stage: str) -> bool:
    manifest = context["manifest"]
    evidence = context["evidence"]
    window = manifest.time_window
    skew = timedelta(seconds=window["clock_skew_seconds"])
    start = datetime.fromisoformat(window["start_time"].replace("Z", "+00:00")) - skew
    end = datetime.fromisoformat(window["end_time"].replace("Z", "+00:00")) + skew
    timestamp = datetime.fromisoformat(evidence[stage][EVIDENCE_TIMESTAMPS[stage]].replace("Z", "+00:00"))
    return start <= timestamp <= end


def _stages(context: dict[str, object]) -> dict[str, dict]:
    return {stage["stage_name"]: stage for stage in context["report"]["stages_breakdown"]}


@given("one matching record for each of the five stages")
def unique_records(context):
    _load_case(context, "routes/cribl-splunk-route")
    evidence = context["evidence"]
    assert set(evidence) == set(EVIDENCE_TIMESTAMPS)
    assert all(context["manifest"].synthetic_marker in json.dumps(record) for record in evidence.values())


@given("every stage timestamp falls inside the manifest window including clock skew")
def all_timestamps_inside(context):
    assert all(_within_window(context, stage) for stage in EVIDENCE_TIMESTAMPS)


@given("two distinct destination records contain the same synthetic marker")
def duplicate_destination(context):
    _load_case(context, "failures/duplicate-marker")
    records = context["evidence"]["destination_indexing"]["records"]
    assert len(records) == 2
    assert len({record["record_id"] for record in records}) == 2
    assert all(record["marker"] == context["manifest"].synthetic_marker for record in records)


@given("the other four stages have one valid matching record each")
def other_records_are_unique(context):
    evidence = context["evidence"]
    assert all(
        isinstance(evidence[stage], dict)
        and context["manifest"].synthetic_marker in json.dumps(evidence[stage])
        and _within_window(context, stage)
        for stage in EVIDENCE_TIMESTAMPS
        if stage != "destination_indexing"
    )


@given("destination indexing, query evaluation, and alert records occur after the capture window")
def late_records(context):
    _load_case(context, "failures/delayed-indexing")
    assert all(
        not _within_window(context, stage) for stage in ("destination_indexing", "query_evaluation", "alert_creation")
    )


@given("source and routing records occur inside the capture window")
def early_records(context):
    assert all(_within_window(context, stage) for stage in ("source_event", "cribl_route"))


@given("no destination record was supplied for the synthetic marker")
def missing_destination(context):
    _load_case(context, "routes/cribl-splunk-route")
    context["evidence"].pop("destination_indexing")
    assert "destination_indexing" not in context["evidence"]


@when("the telemetry proof pack correlates the supplied records")
def correlate(context):
    context["report"] = correlate_pipeline_evidence(context["manifest"], context["evidence"])


@then("each stage is observed and the report is healthy")
def complete_trace(context):
    assert context["report"]["pipeline_health"] == "healthy"
    assert all(stage["status"] == "observed" for stage in _stages(context).values())


@then("destination indexing is unresolved with both matching evidence IDs")
def destination_is_ambiguous(context):
    stage = _stages(context)["destination_indexing"]
    assert stage["status"] == "unresolved"
    assert stage["details"]["matching_evidence_ids"] == ["splunk-hec-rec-5001", "splunk-hec-rec-5002"]


@then("its supplied evidence hash is retained")
def duplicate_hash_retained(context):
    assert len(_stages(context)["destination_indexing"]["raw_evidence_hash"]) == 64


@then("the other four stage observations are retained")
def other_stages_retained(context):
    assert context["report"]["pipeline_health"] == "degraded"
    assert all(
        _stages(context)[STAGE_NAMES[stage]]["status"] == "observed"
        for stage in EVIDENCE_TIMESTAMPS
        if stage != "destination_indexing"
    )


@then("the three late stages are unresolved with their timestamps and evidence hashes")
def late_stages_unresolved(context):
    for name in ("destination_indexing", "query_evaluation", "alert_creation"):
        stage = _stages(context)[name]
        assert stage["status"] == "unresolved"
        assert stage["timestamp"] == context["evidence"][name][EVIDENCE_TIMESTAMPS[name]]
        assert len(stage["raw_evidence_hash"]) == 64


@then("source and routing remain observed")
def early_stages_observed(context):
    assert all(
        _stages(context)[STAGE_NAMES[stage]]["status"] == "observed" for stage in ("source_event", "cribl_route")
    )


@then("destination indexing is missing and the report is broken")
def missing_stage_is_broken(context):
    assert _stages(context)["destination_indexing"]["status"] == "missing"
    assert context["report"]["pipeline_health"] == "broken"


@then("the report describes the status as supplied evidence only")
def report_limits_its_claim(context):
    markdown = render_markdown_report(context["report"])
    assert "BROKEN (NO DESTINATION MARKER EVIDENCE)" in markdown
    assert "Correlates supplied evidence" in markdown
