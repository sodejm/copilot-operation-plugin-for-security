"""Offline action-linked detection report behavior and CLI boundaries."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import cops.reporting.detection as detection
from cops.coverage import load_attack_coverage
from cops.evidence import build_envelope
from cops.reporting.assessment import ReportError
from cops.reporting.cli import command_engagement_detection_validate
from cops.reporting.detection import build_detection_report, render_detection_markdown

MAPPING = next(item for item in load_attack_coverage() if item.coverage_role == "detection")
START = "2026-10-02T10:00:00Z"
END = "2026-10-02T10:01:00Z"


def record(payload, *, tenant="tenant-1", observed_at="2026-10-02T10:00:30Z", product=None):
    if product is None:
        product = MAPPING.evidence_sources[0].product if payload["kind"] == "telemetry" else "test-import"
    return build_envelope(
        acquisition_id="import-1",
        product=product,
        api="records/v1",
        tenant=tenant,
        scope=["lab-1"],
        identity=payload["kind"] + "-" + str(len(payload)),
        locator="local-test",
        payload=payload,
        acquired_at="2026-10-02T10:03:00Z",
        transformed_at="2026-10-02T10:03:00Z",
        observed_at=observed_at,
        request_fingerprint="a" * 64,
        page=1,
    )


def bundle_for(status="detected"):
    action = {
        "action_id": "act-1",
        "technique_id": MAPPING.technique_id,
        "started_at": START,
        "ended_at": END,
        "status": "completed",
    }
    check = {
        "action_id": "act-1",
        "mapping_id": MAPPING.mapping_id,
        "rule_id": "rule-1",
        "collection_status": "complete",
        "correlation_status": "exact",
        "clock_skew_seconds": 0,
        "ingest_lag_seconds": 0,
        "execution_record_id": None,
        "telemetry_record_ids": [],
        "alert_record_ids": [],
        "search_receipt_record_id": None,
    }
    bundle = {
        "schema_version": "cops.detection-validation-input/v1",
        "validation_id": "validation-1",
        "generated_at": "2026-10-02T10:04:00Z",
        "engagement_id": "eng-lab1",
        "tenant": "tenant-1",
        "actions": [action],
        "checks": [check],
        "evidence_envelopes": [],
    }

    def add(payload, field):
        item = record(payload)
        bundle["evidence_envelopes"].append(item)
        if isinstance(check[field], list):
            check[field].append(item["record_id"])
        else:
            check[field] = item["record_id"]

    if status != "unavailable":
        add(
            {
                "kind": "action_execution",
                "action_id": "act-1",
                "technique_id": MAPPING.technique_id,
                "status": "completed",
            },
            "execution_record_id",
        )
        add(
            {
                "kind": "telemetry",
                "action_id": "act-1",
                "rule_id": "rule-1",
                "table_or_log": MAPPING.evidence_sources[0].table_or_log,
                "observed_fields": list(MAPPING.evidence_sources[0].required_fields),
            },
            "telemetry_record_ids",
        )
    if status == "detected":
        add({"kind": "alert", "action_id": "act-1", "rule_id": "rule-1"}, "alert_record_ids")
    if status in {"missed", "ambiguous"}:
        add(
            {
                "kind": "search_receipt",
                "action_id": "act-1",
                "rule_id": "rule-1",
                "status": "complete" if status == "missed" else "partial",
                "result_count": 0,
                "window_start": START,
                "window_end": END,
                "finished_at": "2026-10-02T10:02:00Z",
            },
            "search_receipt_record_id",
        )
    return bundle


@pytest.mark.parametrize("status", ["detected", "missed", "ambiguous", "unavailable"])
def test_outcome_status(status):
    report = build_detection_report(bundle_for(status))
    row = report["checks"][0]
    assert row["status"] == status
    assert row["expected_telemetry"]
    assert row["technique_id"] == MAPPING.technique_id
    assert report["mode"] == "offline_import"
    assert sum(signal["kind"] == "telemetry" and signal["in_window"] for signal in row["observed_signals"]) == (
        status != "unavailable"
    )
    assert sum(signal["kind"] == "alert" and signal["in_window"] for signal in row["observed_signals"]) == (
        status == "detected"
    )
    assert (row["search_evidence"] is not None) == (status in {"missed", "ambiguous"})
    assert row["next_action"]


def test_missing_telemetry_cannot_be_missed():
    bundle = bundle_for("missed")
    telemetry_id = bundle["checks"][0]["telemetry_record_ids"][0]
    bundle["checks"][0]["telemetry_record_ids"] = []
    bundle["evidence_envelopes"] = [item for item in bundle["evidence_envelopes"] if item["record_id"] != telemetry_id]
    row = build_detection_report(bundle)["checks"][0]
    assert row["status"] == "ambiguous"
    assert (
        row["next_action"]
        == "Import in-window telemetry from an expected source with required fields, or document the collection gap."
    )


@pytest.mark.parametrize(
    "product,table,fields",
    [
        ("other-product", None, None),
        (None, "other-log", None),
        (None, None, []),
    ],
)
def test_unexpected_telemetry_cannot_establish_missed(product, table, fields):
    bundle = bundle_for("missed")
    original = bundle["evidence_envelopes"][1]
    payload = original["payload"].copy()
    if table is not None:
        payload["table_or_log"] = table
    if fields is not None:
        payload["observed_fields"] = fields
    replacement = record(payload, product=product)
    bundle["evidence_envelopes"][1] = replacement
    bundle["checks"][0]["telemetry_record_ids"] = [replacement["record_id"]]
    row = build_detection_report(bundle)["checks"][0]
    assert row["status"] == "ambiguous"
    signal = next(item for item in row["observed_signals"] if item["kind"] == "telemetry")
    assert signal["matches_expected_source"] is (product is None and table is None)
    assert signal["has_required_fields"] is (False if fields is not None else None)
    assert "No in-window telemetry with an expected source and required fields" in row["limitations"]


@pytest.mark.parametrize("value", [{}, ["TimeGenerated", "TimeGenerated"], [12]])
def test_invalid_observed_fields_rejected(value):
    bundle = bundle_for("missed")
    payload = bundle["evidence_envelopes"][1]["payload"] | {"observed_fields": value}
    replacement = record(payload)
    bundle["evidence_envelopes"][1] = replacement
    bundle["checks"][0]["telemetry_record_ids"] = [replacement["record_id"]]
    with pytest.raises(ReportError, match="observed telemetry fields"):
        build_detection_report(bundle)


def test_unlinked_evidence_cannot_be_ignored():
    bundle = bundle_for("missed")
    bundle["evidence_envelopes"].append(record({"kind": "alert", "action_id": "act-1", "rule_id": "rule-1"}))
    with pytest.raises(ReportError, match="unreferenced evidence"):
        build_detection_report(bundle)


def test_aggregate_link_count_bounds_reused_evidence(monkeypatch):
    bundle = bundle_for("detected")
    second_check = bundle["checks"][0].copy()
    second_check["rule_id"] = "rule-2"
    second_check["telemetry_record_ids"] = []
    second_check["alert_record_ids"] = []
    bundle["checks"].append(second_check)
    monkeypatch.setattr(detection, "_MAX_LINKED_RECORDS", 3)
    with pytest.raises(ReportError, match="too many linked evidence records"):
        build_detection_report(bundle)


@pytest.mark.parametrize("field", ["actions", "checks"])
def test_empty_work_is_rejected(field):
    bundle = bundle_for("detected")
    bundle[field] = []
    with pytest.raises(ReportError):
        build_detection_report(bundle)


def test_every_action_needs_a_check():
    bundle = bundle_for("detected")
    bundle["actions"].append(
        {
            "action_id": "act-2",
            "technique_id": MAPPING.technique_id,
            "started_at": START,
            "ended_at": END,
            "status": "not_executed",
        }
    )
    with pytest.raises(ReportError, match="every action"):
        build_detection_report(bundle)


def test_not_executed_action_rejects_execution_evidence():
    bundle = bundle_for("detected")
    bundle["actions"][0]["status"] = "not_executed"
    with pytest.raises(ReportError, match="not_executed action has execution evidence"):
        build_detection_report(bundle)


def test_search_must_cover_skew_and_lag():
    bundle = bundle_for("missed")
    bundle["checks"][0]["clock_skew_seconds"] = 10
    bundle["checks"][0]["ingest_lag_seconds"] = 30
    row = build_detection_report(bundle)["checks"][0]
    assert row["status"] == "ambiguous"
    assert row["search_evidence"]["covers_expanded_window"] is False


def test_cross_tenant_evidence_rejected():
    bundle = bundle_for("detected")
    bundle["evidence_envelopes"][0] = record(bundle["evidence_envelopes"][0]["payload"], tenant="tenant-2")
    with pytest.raises(ReportError, match="cross-tenant"):
        build_detection_report(bundle)


def test_mismatched_action_and_rule_evidence_rejected():
    bundle = bundle_for("detected")
    alien = record({"kind": "alert", "action_id": "act-2", "rule_id": "rule-1"})
    bundle["evidence_envelopes"].append(alien)
    bundle["checks"][0]["alert_record_ids"] = [alien["record_id"]]
    with pytest.raises(ReportError, match="does not match"):
        build_detection_report(bundle)


def test_zero_result_receipt_conflicting_with_alert_is_ambiguous():
    bundle = bundle_for("missed")
    alert = record({"kind": "alert", "action_id": "act-1", "rule_id": "rule-1"})
    bundle["evidence_envelopes"].append(alert)
    bundle["checks"][0]["alert_record_ids"] = [alert["record_id"]]
    assert build_detection_report(bundle)["checks"][0]["status"] == "ambiguous"


def test_markdown_excludes_evidence_payload_and_source_locator():
    bundle = bundle_for("detected")
    report = build_detection_report(bundle)
    markdown = render_detection_markdown(report)
    assert "local-test" not in markdown
    assert "test-import" not in markdown
    assert "act-1" in markdown
    assert "Expected in-window telemetry" in markdown
    assert "| detected | 1 | 1 |" in markdown
    assert "next action: Verify the imported alert's source authenticity" in markdown


def test_out_of_window_alert_is_visible_but_not_a_detection():
    bundle = bundle_for("detected")
    original = bundle["evidence_envelopes"][-1]
    late = record(original["payload"], observed_at="2026-10-02T10:05:00Z")
    bundle["evidence_envelopes"][-1] = late
    bundle["checks"][0]["alert_record_ids"] = [late["record_id"]]
    row = build_detection_report(bundle)["checks"][0]
    assert row["status"] == "ambiguous"
    assert any(signal["kind"] == "alert" and not signal["in_window"] for signal in row["observed_signals"])


def test_cli_writes_private_exclusive_files(tmp_path: Path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(bundle_for("detected")), encoding="utf-8")
    json_output = tmp_path / "output.json"
    markdown_output = tmp_path / "output.md"
    args = SimpleNamespace(input=source, json_output=json_output, markdown_output=markdown_output)
    assert command_engagement_detection_validate(args) == 0
    assert json.loads(json_output.read_text(encoding="utf-8"))["checks"][0]["status"] == "detected"
    if os.name == "posix":
        assert json_output.stat().st_mode & 0o777 == 0o600
        assert markdown_output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ReportError, match="already exists"):
        command_engagement_detection_validate(args)


def test_input_rejects_unbounded_integer_and_unknown_mapping():
    bundle = bundle_for("missed")
    bundle["checks"][0]["clock_skew_seconds"] = True
    with pytest.raises(ReportError, match="clock_skew"):
        build_detection_report(bundle)
    bundle = bundle_for("missed")
    bundle["checks"][0]["mapping_id"] = "COPS-COV-not-real"
    with pytest.raises(ReportError, match="mapping"):
        build_detection_report(bundle)


@pytest.mark.parametrize(
    "field,value",
    [
        ("action_status", []),
        ("collection_status", []),
        ("correlation_status", {}),
        ("evidence_kind", []),
        ("search_status", []),
    ],
)
def test_unhashable_untrusted_values_are_report_errors(field, value):
    bundle = bundle_for("missed" if field == "search_status" else "detected")
    if field == "action_status":
        bundle["actions"][0]["status"] = value
    elif field == "evidence_kind":
        bundle["evidence_envelopes"][0]["payload"]["kind"] = value
    elif field == "search_status":
        receipt = bundle["evidence_envelopes"][-1]["payload"] | {"status": value}
        bundle["evidence_envelopes"][-1] = record(receipt)
    else:
        bundle["checks"][0][field] = value
    with pytest.raises(ReportError):
        build_detection_report(bundle)
