"""Evidence-bounded, offline validation of engagement detection outcomes."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from cops.coverage import CoverageError, CoverageMapping, load_attack_coverage
from cops.evidence.canonical import EvidenceError, timestamp
from cops.evidence.validation import validate_envelope

from .assessment import ReportError

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_ENGAGEMENT_ID = re.compile(r"^eng-[a-z0-9_-]{4,64}$")
_ROOT_KEYS = {
    "schema_version",
    "validation_id",
    "generated_at",
    "engagement_id",
    "tenant",
    "actions",
    "checks",
    "evidence_envelopes",
}
_ACTION_KEYS = {"action_id", "technique_id", "started_at", "ended_at", "status"}
_CHECK_KEYS = {
    "action_id",
    "mapping_id",
    "rule_id",
    "collection_status",
    "correlation_status",
    "clock_skew_seconds",
    "ingest_lag_seconds",
    "execution_record_id",
    "telemetry_record_ids",
    "alert_record_ids",
    "search_receipt_record_id",
}
_KINDS = {"action_execution", "telemetry", "alert", "search_receipt"}
_MAX_LINKED_RECORDS = 10000
_NOTICE = "Imported record hashes prove internal integrity only. Source authenticity, execution authorization, and provider-wide search completeness require separate evidence."


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or value.keys() != keys:
        raise ReportError(f"{label} must have exactly the required fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ReportError(f"invalid {label}")
    return value


def _list(value: Any, label: str, *, maximum: int = 1000) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        raise ReportError(f"{label} must be a bounded array")
    return value


def _record_ids(value: Any, label: str) -> list[str]:
    result = [_identifier(item, label) for item in _list(value, label)]
    if len(result) != len(set(result)):
        raise ReportError(f"duplicate {label}")
    return result


def _time(value: Any, label: str):
    try:
        return timestamp(value)
    except EvidenceError as error:
        raise ReportError(f"invalid {label}") from error


def _evidence(item: Any, tenant: str) -> dict[str, Any]:
    try:
        envelope = validate_envelope(item)
    except (EvidenceError, TypeError, KeyError) as error:
        raise ReportError("invalid evidence envelope") from error
    if envelope["source"]["tenant"] != tenant:
        raise ReportError("cross-tenant evidence")
    payload = envelope["payload"]
    if type(payload) is not dict or type(payload.get("kind")) is not str or payload["kind"] not in _KINDS:
        raise ReportError("invalid detection evidence payload")
    kind = payload["kind"]
    expected = (
        {"kind", "action_id", "technique_id", "status"}
        if kind == "action_execution"
        else {"kind", "action_id", "rule_id"}
    )
    if kind == "telemetry":
        expected |= {"table_or_log", "observed_fields"}
    if kind == "search_receipt":
        expected |= {"status", "result_count", "window_start", "window_end", "finished_at"}
    _object(payload, expected, "detection evidence payload")
    _identifier(payload["action_id"], "evidence action ID")
    if kind == "action_execution":
        if type(payload["technique_id"]) is not str or payload["status"] != "completed":
            raise ReportError("invalid execution evidence")
    else:
        _identifier(payload["rule_id"], "evidence rule ID")
    if kind == "telemetry":
        if type(payload["table_or_log"]) is not str or not 1 <= len(payload["table_or_log"]) <= 128:
            raise ReportError("invalid telemetry table or log")
        observed_fields = _list(payload["observed_fields"], "observed telemetry fields", maximum=100)
        if any(type(field) is not str or not 1 <= len(field) <= 128 for field in observed_fields) or len(
            observed_fields
        ) != len(set(observed_fields)):
            raise ReportError("invalid observed telemetry fields")
    if kind == "search_receipt":
        if (
            type(payload["status"]) is not str
            or payload["status"] not in {"complete", "partial"}
            or type(payload["result_count"]) is not int
            or not 0 <= payload["result_count"] <= 1000000
        ):
            raise ReportError("invalid search receipt")
        if (
            not _time(payload["window_start"], "search start")
            <= _time(payload["window_end"], "search end")
            <= _time(payload["finished_at"], "search finish")
        ):
            raise ReportError("invalid search receipt window")
    return envelope


def _linked(
    records: dict[str, dict[str, Any]], record_id: str | None, kind: str, action_id: str, rule_id: str | None = None
) -> dict[str, Any] | None:
    if record_id is None:
        return None
    record = records.get(record_id)
    if record is None:
        raise ReportError("unknown evidence record")
    payload = record["payload"]
    if (
        payload["kind"] != kind
        or payload["action_id"] != action_id
        or (rule_id is not None and payload["rule_id"] != rule_id)
    ):
        raise ReportError("evidence reference does not match action and rule")
    return record


def _observed(record: dict[str, Any] | None):
    return (
        None
        if record is None or record["observed"]["at"] is None
        else _time(record["observed"]["at"], "observation time")
    )


def build_detection_report(bundle: Any, *, mappings: list[CoverageMapping] | None = None) -> dict[str, Any]:
    """Classify only action-linked imported evidence; no provider calls are made."""
    data = _object(bundle, _ROOT_KEYS, "detection input")
    if data["schema_version"] != "cops.detection-validation-input/v1":
        raise ReportError("unsupported detection input version")
    for key in ("validation_id", "engagement_id", "tenant"):
        _identifier(data[key], key)
    if not _ENGAGEMENT_ID.fullmatch(data["engagement_id"]):
        raise ReportError("invalid engagement_id")
    _time(data["generated_at"], "generation time")
    actions: dict[str, dict[str, Any]] = {}
    action_items = _list(data["actions"], "actions", maximum=500)
    if not action_items:
        raise ReportError("at least one action is required")
    for raw in action_items:
        action = _object(raw, _ACTION_KEYS, "action")
        action_id = _identifier(action["action_id"], "action ID")
        if action_id in actions:
            raise ReportError("duplicate action ID")
        if type(action["technique_id"]) is not str or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", action["technique_id"]):
            raise ReportError("invalid ATT&CK technique ID")
        if type(action["status"]) is not str or action["status"] not in {"completed", "not_executed"}:
            raise ReportError("invalid action status")
        if _time(action["started_at"], "action start") > _time(action["ended_at"], "action end"):
            raise ReportError("invalid action window")
        actions[action_id] = action
    records: dict[str, dict[str, Any]] = {}
    for raw in _list(data["evidence_envelopes"], "evidence envelopes", maximum=2000):
        record = _evidence(raw, data["tenant"])
        if record["record_id"] in records:
            raise ReportError("duplicate evidence record")
        records[record["record_id"]] = record
    try:
        catalog = {item.mapping_id: item for item in (mappings if mappings is not None else load_attack_coverage())}
    except CoverageError as error:
        raise ReportError("cannot load ATT&CK coverage catalog") from error
    rows = []
    seen_checks = set()
    referenced_records: set[str] = set()
    checked_actions: set[str] = set()
    linked_record_count = 0
    check_items = _list(data["checks"], "checks", maximum=1000)
    if not check_items:
        raise ReportError("at least one detection check is required")
    for raw in check_items:
        check = _object(raw, _CHECK_KEYS, "detection check")
        action_id = _identifier(check["action_id"], "check action ID")
        rule_id = _identifier(check["rule_id"], "rule ID")
        mapping_id = _identifier(check["mapping_id"], "mapping ID")
        action = actions.get(action_id)
        mapping = catalog.get(mapping_id)
        if (
            action is None
            or mapping is None
            or mapping.technique_id != action["technique_id"]
            or mapping.coverage_role != "detection"
        ):
            raise ReportError("check does not match a detection mapping and action")
        key = (action_id, mapping_id, rule_id)
        if key in seen_checks:
            raise ReportError("duplicate detection check")
        seen_checks.add(key)
        checked_actions.add(action_id)
        if (
            type(check["collection_status"]) is not str
            or check["collection_status"] not in {"complete", "partial", "unavailable"}
            or type(check["correlation_status"]) is not str
            or check["correlation_status"] not in {"exact", "ambiguous", "unavailable"}
        ):
            raise ReportError("invalid collection or correlation status")
        for field, maximum in (("clock_skew_seconds", 3600), ("ingest_lag_seconds", 86400)):
            if type(check[field]) is not int or not 0 <= check[field] <= maximum:
                raise ReportError(f"invalid {field}")
        for field in ("execution_record_id", "search_receipt_record_id"):
            if check[field] is not None:
                _identifier(check[field], field)
        telemetry_ids = _record_ids(check["telemetry_record_ids"], "telemetry record IDs")
        alert_ids = _record_ids(check["alert_record_ids"], "alert record IDs")
        linked_record_count += len(telemetry_ids) + len(alert_ids)
        linked_record_count += (check["execution_record_id"] is not None) + (
            check["search_receipt_record_id"] is not None
        )
        if linked_record_count > _MAX_LINKED_RECORDS:
            raise ReportError("too many linked evidence records")
        referenced_records.update(
            item
            for item in [check["execution_record_id"], *telemetry_ids, *alert_ids, check["search_receipt_record_id"]]
            if item is not None
        )
        execution = _linked(records, check["execution_record_id"], "action_execution", action_id)
        if action["status"] == "not_executed" and execution is not None:
            raise ReportError("not_executed action has execution evidence")
        if execution is not None and execution["payload"]["technique_id"] != action["technique_id"]:
            raise ReportError("execution technique mismatch")
        telemetry = [_linked(records, record_id, "telemetry", action_id, rule_id) for record_id in telemetry_ids]
        alerts = [_linked(records, record_id, "alert", action_id, rule_id) for record_id in alert_ids]
        receipt = _linked(records, check["search_receipt_record_id"], "search_receipt", action_id, rule_id)
        start = _time(action["started_at"], "action start") - timedelta(seconds=check["clock_skew_seconds"])
        end = _time(action["ended_at"], "action end") + timedelta(
            seconds=check["clock_skew_seconds"] + check["ingest_lag_seconds"]
        )
        signals = []
        expected_sources = {
            (source.product, source.table_or_log): set(source.required_fields) for source in mapping.evidence_sources
        }
        for kind, group in (
            ("action_execution", [execution] if execution is not None else []),
            ("telemetry", telemetry),
            ("alert", alerts),
        ):
            for record in group:
                observed = _observed(record)
                expected_fields = (
                    expected_sources.get((record["source"]["product"], record["payload"].get("table_or_log")))
                    if kind == "telemetry"
                    else None
                )
                signals.append(
                    {
                        "kind": kind,
                        "record_id": record["record_id"],
                        "observed_at": record["observed"]["at"],
                        "in_window": observed is not None and start <= observed <= end,
                        "matches_expected_source": expected_fields is not None if kind == "telemetry" else None,
                        "has_required_fields": set(record["payload"]["observed_fields"]) >= expected_fields
                        if expected_fields is not None
                        else None,
                    }
                )
        execution_seen = any(item["kind"] == "action_execution" and item["in_window"] for item in signals)
        telemetry_seen = any(
            item["kind"] == "telemetry" and item["in_window"] and item["has_required_fields"] is True
            for item in signals
        )
        alert_seen = any(item["kind"] == "alert" and item["in_window"] for item in signals)
        receipt_payload = receipt["payload"] if receipt is not None else None
        receipt_covering = (
            receipt_payload is not None
            and _time(receipt_payload["window_start"], "search start") <= start
            and _time(receipt_payload["window_end"], "search end") >= end
        )
        zero_search = (
            receipt_covering and receipt_payload["status"] == "complete" and receipt_payload["result_count"] == 0
        )
        conflicting_search = zero_search and bool(alerts)
        limitations = []
        if not execution_seen:
            limitations.append("No in-window execution observation")
        if check["collection_status"] != "complete":
            limitations.append("Collection not declared complete")
        if check["correlation_status"] != "exact":
            limitations.append("Correlation not exact")
        if not telemetry_seen:
            limitations.append("No in-window telemetry with an expected source and required fields")
        if not receipt_covering:
            limitations.append("No covering search receipt")
        if conflicting_search:
            limitations.append("Alert conflicts with zero-result search")
        if action["status"] != "completed" or not execution_seen or check["collection_status"] == "unavailable":
            status = "unavailable"
        elif check["correlation_status"] == "exact" and alert_seen and not conflicting_search:
            status = "detected"
        elif (
            check["collection_status"] == "complete"
            and check["correlation_status"] == "exact"
            and telemetry_seen
            and zero_search
            and not alerts
        ):
            status = "missed"
        else:
            status = "ambiguous"
        if action["status"] != "completed":
            next_action = "Complete an authorized action and import its execution observation."
        elif not execution_seen:
            next_action = "Import an in-window execution observation for this action."
        elif check["collection_status"] == "unavailable":
            next_action = "Restore telemetry collection or document why it is unavailable, then validate again."
        elif conflicting_search:
            next_action = "Reconcile the alert with the zero-result search receipt before classifying this rule."
        elif check["correlation_status"] != "exact":
            next_action = "Establish exact action-to-rule correlation and validate again."
        elif status == "detected":
            next_action = "Verify the imported alert's source authenticity before relying on this detection result."
        elif not telemetry_seen:
            next_action = "Import in-window telemetry from an expected source with required fields, or document the collection gap."
        elif not receipt_covering or receipt_payload["status"] != "complete":
            next_action = "Import a completed search receipt covering the expanded action window."
        elif status == "missed":
            next_action = "Review the rule and rerun bounded detection validation after remediation."
        else:
            next_action = "Reconcile the supplied evidence and validate this action again."
        rows.append(
            {
                "action_id": action_id,
                "technique_id": action["technique_id"],
                "mapping_id": mapping_id,
                "rule_id": rule_id,
                "status": status,
                "action_window": [action["started_at"], action["ended_at"]],
                "expanded_window": [start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z")],
                "expected_telemetry": [
                    {
                        "product": source.product,
                        "table_or_log": source.table_or_log,
                        "required_fields": list(source.required_fields),
                        "onboarding_status": source.onboarding_status,
                    }
                    for source in mapping.evidence_sources
                ],
                "observed_signals": signals,
                "search_evidence": None
                if receipt_payload is None
                else {
                    "record_id": receipt["record_id"],
                    "status": receipt_payload["status"],
                    "result_count": receipt_payload["result_count"],
                    "covers_expanded_window": receipt_covering,
                },
                "declared_collection_status": check["collection_status"],
                "declared_correlation_status": check["correlation_status"],
                "clock_skew_seconds": check["clock_skew_seconds"],
                "ingest_lag_seconds": check["ingest_lag_seconds"],
                "evidence_record_ids": [
                    item
                    for item in [
                        check["execution_record_id"],
                        *telemetry_ids,
                        *alert_ids,
                        check["search_receipt_record_id"],
                    ]
                    if item is not None
                ],
                "limitations": limitations,
                "next_action": next_action,
            }
        )
    if checked_actions != set(actions):
        raise ReportError("every action requires a detection check")
    if referenced_records != set(records):
        raise ReportError("unreferenced evidence record")
    return {
        "schema_version": "cops.detection-validation-report/v1",
        "validation_id": data["validation_id"],
        "generated_at": data["generated_at"],
        "engagement_id": data["engagement_id"],
        "tenant": data["tenant"],
        "mode": "offline_import",
        "source_notice": _NOTICE,
        "checks": rows,
    }


def render_detection_markdown(report: dict[str, Any]) -> str:
    """Summarize bounded identifiers and fixed labels, never raw evidence payloads."""
    lines = [
        "# Offline detection validation",
        "",
        f"Engagement: `{report['engagement_id']}`",
        f"Tenant: `{report['tenant']}`",
        "",
        report["source_notice"],
        "",
        "| Action | ATT&CK | Rule | Measured status | Expected in-window telemetry | In-window alerts |",
        "| --- | --- | --- | --- | ---: | ---: |",
    ]
    for row in report["checks"]:
        telemetry_count = sum(
            signal["kind"] == "telemetry" and signal["in_window"] and signal["has_required_fields"] is True
            for signal in row["observed_signals"]
        )
        alert_count = sum(signal["kind"] == "alert" and signal["in_window"] for signal in row["observed_signals"])
        lines.append(
            f"| `{row['action_id']}` | `{row['technique_id']}` | `{row['rule_id']}` | {row['status']} | {telemetry_count} | {alert_count} |"
        )
        if row["limitations"]:
            lines.append(f"\n`{row['action_id']}` limitations: {'; '.join(row['limitations'])}.")
        lines.append(f"`{row['action_id']}` next action: {row['next_action']}")
    lines.extend(
        [
            "",
            "A missing signal or unavailable telemetry does not establish prevention. See the private JSON report for exact evidence IDs, windows, expected sources, and limitations.",
            "",
        ]
    )
    return "\n".join(lines)
