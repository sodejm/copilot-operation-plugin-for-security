"""Multi-stage telemetry-to-detection correlation engine."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from math import isfinite
from typing import Any

from .models import ProofError, RunManifest, StageObservation
from .redaction import redact_dict


def _compute_hash(data: Any) -> str:
    """Compute deterministic SHA-256 hash of evidence content."""
    serialized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _parse_iso(ts_str: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


def _matching_records(data: Any, marker: str) -> list[dict[str, Any]]:
    """Match distinct records, not repeated marker fields within one record."""
    if not isinstance(data, dict):
        return []
    if "records" in data:
        records = data["records"] if isinstance(data["records"], list) else []
    else:
        records = [data]
    return [record for record in records if isinstance(record, dict) and marker in json.dumps(record)]


def _capture_window(manifest: RunManifest) -> tuple[datetime, datetime]:
    window = manifest.time_window
    start = _parse_iso(window.get("start_time"))
    end = _parse_iso(window.get("end_time"))
    try:
        skew_seconds = float(window.get("clock_skew_seconds", 0))
    except (TypeError, ValueError) as exc:
        raise ProofError("Manifest time window has invalid clock_skew_seconds") from exc
    if start is None or end is None or start > end or skew_seconds < 0 or not isfinite(skew_seconds):
        raise ProofError("Manifest time window requires ordered, timezone-aware bounds and nonnegative clock skew")
    try:
        skew = timedelta(seconds=skew_seconds)
        return start - skew, end + skew
    except OverflowError as exc:
        raise ProofError("Manifest clock skew exceeds supported timestamp range") from exc


def correlate_pipeline_evidence(manifest: RunManifest, evidence_files: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Correlate telemetry evidence across all lifecycle stages for a synthetic marker."""
    marker = manifest.synthetic_marker
    expected_tenant = manifest.destination.get("tenant_or_workspace_id")
    stages: list[StageObservation] = []
    diagnostics: list[str] = []
    next_checks: list[str] = []
    window_start, window_end = _capture_window(manifest)
    matches = {name: _matching_records(evidence_files.get(name), marker) for name in (
        "source_event", "cribl_route", "destination_indexing", "query_evaluation", "alert_creation"
    )}

    # 1. Source Emission Stage
    src_data = matches["source_event"][0] if matches["source_event"] else None
    if src_data:
        ev_id = src_data.get("event_id", f"src-{marker}")
        ts = src_data.get("timestamp", src_data.get("TimeGenerated", src_data.get("_time", "")))

        # Check tenant isolation
        evt_tenant = src_data.get("tenant_id", expected_tenant)
        if expected_tenant and evt_tenant != expected_tenant:
            stages.append(StageObservation(
                stage_name="source_emission",
                status="unresolved",
                component="Source Provider",
                evidence_id=ev_id,
                timestamp=ts,
                raw_evidence_hash=_compute_hash(src_data),
                details={"reason": f"Cross-tenant collision: event tenant '{evt_tenant}' != expected '{expected_tenant}'"},
            ))
            diagnostics.append(f"Source event tenant '{evt_tenant}' conflicts with expected tenant '{expected_tenant}'.")
        else:
            stages.append(StageObservation(
                stage_name="source_emission",
                status="observed",
                component="Source Telemetry Provider",
                evidence_id=ev_id,
                timestamp=ts,
                raw_evidence_hash=_compute_hash(src_data),
                details={"marker": marker, "event_type": manifest.source_event_type},
            ))
    else:
        stages.append(StageObservation(
            stage_name="source_emission",
            status="missing",
            component="Source Telemetry Provider",
            evidence_id="MISSING",
            details={"reason": f"Synthetic marker '{marker}' was not found in source event records."},
        ))
        diagnostics.append(f"No source evidence record contains synthetic marker '{marker}'.")
        next_checks.append("Verify source audit logging configuration and test event generator.")

    # 2. Pipeline Routing Stage (Cribl Stream)
    cribl_data = matches["cribl_route"][0] if matches["cribl_route"] else None
    if cribl_data:
        c_status = cribl_data.get("status", "routed")
        ts = cribl_data.get("timestamp", "")
        if c_status == "dropped" or cribl_data.get("filtered_out"):
            stages.append(StageObservation(
                stage_name="pipeline_routing",
                status="unresolved",
                component="Cribl Stream Worker",
                evidence_id=cribl_data.get("route_id", "cribl-route-01"),
                timestamp=ts,
                raw_evidence_hash=_compute_hash(cribl_data),
                details={"reason": "Supplied Cribl route record marks this event as filtered or dropped."},
            ))
            diagnostics.append("Supplied Cribl route evidence marks the synthetic marker event as dropped or filtered.")
            next_checks.append("Inspect Cribl route filter rules and pipeline regex expressions.")
        else:
            stages.append(StageObservation(
                stage_name="pipeline_routing",
                status="observed",
                component="Cribl Stream Worker",
                evidence_id=cribl_data.get("route_id", "cribl-route-01"),
                timestamp=ts,
                raw_evidence_hash=_compute_hash(cribl_data),
                details=redact_dict(cribl_data.get("metrics", {})),
            ))
    else:
        stages.append(StageObservation(
            stage_name="pipeline_routing",
            status="missing",
            component="Cribl Stream Worker",
            evidence_id="MISSING",
            details={"reason": f"No supplied Cribl route record contains marker '{marker}'."},
        ))
        diagnostics.append("No Cribl Stream evidence record contains the synthetic marker.")
        next_checks.append("Check Cribl Stream receiver health and worker node connectivity.")

    # 3. Destination Indexing Stage (Splunk Index or Sentinel Table)
    dest_data = matches["destination_indexing"][0] if matches["destination_indexing"] else None
    dest_component = "Splunk HEC / Indexer" if manifest.pipeline_route == "cribl_to_splunk" else "Log Analytics Workspace"
    dest_indexed = False
    if dest_data:
        dest_indexed = True
        ts = dest_data.get("indexed_time", dest_data.get("TimeGenerated", dest_data.get("_time", "")))
        stages.append(StageObservation(
            stage_name="destination_indexing",
            status="observed",
            component=dest_component,
            evidence_id=dest_data.get("record_id", f"idx-{marker}"),
            timestamp=ts,
            raw_evidence_hash=_compute_hash(dest_data),
            details={"target_container": manifest.destination.get("target_container")},
        ))
    else:
        stages.append(StageObservation(
            stage_name="destination_indexing",
            status="missing",
            component=dest_component,
            evidence_id="MISSING",
            details={"reason": f"No supplied destination record contains marker '{marker}'."},
        ))
        diagnostics.append(f"No {dest_component} evidence record contains the synthetic marker.")
        next_checks.append("Verify destination credentials, HEC token, or Data Collection Rule permissions.")

    # 4. Query Evaluation Stage
    query_data = matches["query_evaluation"][0] if matches["query_evaluation"] else None
    rule_name = manifest.detection_rule.get("rule_name", "Detection Rule")
    if query_data:
        matched_count = query_data.get("matched_count")
        ts = query_data.get("evaluation_time", "")
        if type(matched_count) is not int or matched_count < 0:
            stages.append(StageObservation(
                stage_name="query_evaluation",
                status="unresolved",
                component=f"{rule_name} (Scheduled Query)",
                evidence_id=query_data.get("execution_id", "exec-01"),
                timestamp=ts,
                raw_evidence_hash=_compute_hash(query_data),
                details={"reason": "Supplied rule execution record has invalid matched_count; expected a nonnegative integer."},
            ))
            diagnostics.append(f"Supplied execution record for detection rule '{rule_name}' has invalid matched_count.")
            next_checks.append("Verify the scheduled query export includes a nonnegative integer matched_count.")
        elif matched_count > 0:
            stages.append(StageObservation(
                stage_name="query_evaluation",
                status="observed",
                component=f"{rule_name} (Scheduled Query)",
                evidence_id=query_data.get("execution_id", "exec-01"),
                timestamp=ts,
                raw_evidence_hash=_compute_hash(query_data),
                details={"matched_count": matched_count, "rule_id": manifest.detection_rule.get("rule_id")},
            ))
        else:
            stages.append(StageObservation(
                stage_name="query_evaluation",
                status="unresolved",
                component=f"{rule_name} (Scheduled Query)",
                evidence_id=query_data.get("execution_id", "exec-01"),
                timestamp=ts,
                raw_evidence_hash=_compute_hash(query_data),
                details={"reason": "Supplied rule execution record reports zero matching rows."},
            ))
            diagnostics.append(f"Supplied execution record for detection rule '{rule_name}' reports no marker match.")
            next_checks.append("Review detection rule KQL/SPL query logic, time bounds, and threshold settings.")
    else:
        stages.append(StageObservation(
            stage_name="query_evaluation",
            status="missing",
            component=f"{rule_name} (Scheduled Query)",
            evidence_id="MISSING",
            details={"reason": "No supplied execution record contains the marker."},
        ))
        diagnostics.append(f"No execution evidence record was found for scheduled detection query '{rule_name}'.")
        next_checks.append("Check SIEM scheduled search / analytics rule status and schedule interval.")

    # 5. Alert / Incident Creation Stage
    alert_data = matches["alert_creation"][0] if matches["alert_creation"] else None
    alert_component = "Splunk Notable Event" if manifest.pipeline_route == "cribl_to_splunk" else "Sentinel Incident"
    alert_created = False
    if alert_data:
        alert_created = True
        ts = alert_data.get("created_time", alert_data.get("TimeGenerated", ""))
        stages.append(StageObservation(
            stage_name="alert_creation",
            status="observed",
            component=alert_component,
            evidence_id=alert_data.get("alert_id", "alert-01"),
            timestamp=ts,
            raw_evidence_hash=_compute_hash(alert_data),
            details={"severity": alert_data.get("severity", "high")},
        ))
    else:
        stages.append(StageObservation(
            stage_name="alert_creation",
            status="missing",
            component=alert_component,
            evidence_id="MISSING",
            details={"reason": "No supplied alert or incident evidence record contains the marker."},
        ))
        if dest_indexed and not alert_created:
            diagnostics.append("A destination marker record was supplied, but no matching alert evidence was supplied.")
            next_checks.append("Check alert creation suppression rules, throttling window, and grouping settings.")

    # Resolve ambiguous or out-of-window evidence without erasing stage-specific findings.
    stage_evidence = (
        ("source_event", "event_id"),
        ("cribl_route", "route_id"),
        ("destination_indexing", "record_id"),
        ("query_evaluation", "execution_id"),
        ("alert_creation", "alert_id"),
    )
    for index, (name, id_field) in enumerate(stage_evidence):
        records = matches[name]
        if not records:
            continue
        stage = stages[index]
        details = dict(stage.details)
        reasons: list[str] = []
        if len(records) > 1:
            reasons.append(f"Duplicate marker: {len(records)} matching records at this stage.")
            details["matching_record_count"] = len(records)
            details["matching_evidence_ids"] = [record.get(id_field, "MISSING") for record in records]
            diagnostics.append(f"Duplicate marker records make {stage.stage_name} ambiguous.")
            next_checks.append(f"Inspect all matching {stage.stage_name} records and identify the unique run event.")
        timestamp = _parse_iso(stage.timestamp)
        if timestamp is None:
            reasons.append("Stage evidence has no valid timezone-aware timestamp.")
            diagnostics.append(f"{stage.stage_name} evidence has no valid timestamp.")
            next_checks.append(f"Verify the {stage.stage_name} timestamp and its timezone in source evidence.")
        elif timestamp < window_start or timestamp > window_end:
            reasons.append("Stage timestamp is outside the manifest capture window, including clock skew.")
            diagnostics.append(f"{stage.stage_name} evidence timestamp is outside the scoped capture window.")
            next_checks.append(f"Inspect {stage.stage_name} collection latency and the manifest time window.")
        if reasons:
            details["reason"] = "; ".join(filter(None, [details.get("reason"), *reasons]))
        stages[index] = replace(
            stage,
            status="unresolved" if reasons else stage.status,
            raw_evidence_hash=_compute_hash(evidence_files[name]),
            details=details,
        )

    # Calculate Summary Metrics
    observed_count = sum(1 for s in stages if s.status == "observed")
    missing_count = sum(1 for s in stages if s.status == "missing")
    unresolved_count = sum(1 for s in stages if s.status == "unresolved")

    # Pipeline health classification
    if observed_count == len(stages):
        health = "healthy"
    elif dest_indexed:
        health = "degraded"
    else:
        health = "broken"

    # Compute latency between first and last observed timestamps
    timestamps = []
    for stage in stages:
        if stage.status == "observed":
            timestamp = _parse_iso(stage.timestamp)
            if timestamp is not None:
                timestamps.append(timestamp)
    total_latency = 0.0
    if len(timestamps) >= 2:
        total_latency = round((max(timestamps) - min(timestamps)).total_seconds(), 2)

    return {
        "schema_version": "cops.proof-report/v1",
        "report_id": f"REPORT-PROOF-{manifest.run_id}",
        "run_id": manifest.run_id,
        "synthetic_marker": marker,
        "route_type": manifest.pipeline_route,
        "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "pipeline_health": health,
        "summary": {
            "total_expected_stages": len(stages),
            "observed_stages_count": observed_count,
            "missing_stages_count": missing_count,
            "unresolved_stages_count": unresolved_count,
            "total_latency_seconds": total_latency,
            "detection_fired": stages[-1].status == "observed",
        },
        "stages_breakdown": [s.to_dict() for s in stages],
        "diagnostics": diagnostics if diagnostics else ["All five supplied stage records passed correlation checks."],
        "next_recommended_checks": next_checks if next_checks else ["Review the source systems and continue scoped synthetic monitoring."],
        "privacy_statement": (
            "Use synthetic markers and sanitize source evidence before running this offline tool. "
            "Only Cribl metrics in the stage details receive built-in redaction; IDs and other details can appear in reports. "
            f"Operators must enforce the configured {manifest.evidence_capture_policy.get('retention_days', 30)}-day retention policy."
        ),
    }
