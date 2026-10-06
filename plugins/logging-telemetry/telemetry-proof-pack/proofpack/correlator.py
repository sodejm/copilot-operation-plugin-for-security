"""Multi-stage telemetry-to-detection correlation engine."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from .models import RunManifest, StageObservation
from .redaction import redact_dict


def _compute_hash(data: Any) -> str:
    """Compute deterministic SHA-256 hash of evidence content."""
    serialized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _parse_iso(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def correlate_pipeline_evidence(manifest: RunManifest, evidence_files: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Correlate telemetry evidence across all lifecycle stages for a synthetic marker."""
    marker = manifest.synthetic_marker
    expected_tenant = manifest.destination.get("tenant_or_workspace_id")
    stages: list[StageObservation] = []
    diagnostics: list[str] = []
    next_checks: list[str] = []

    # 1. Source Emission Stage
    src_data = evidence_files.get("source_event")
    if src_data and marker in json.dumps(src_data):
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
        diagnostics.append(f"Synthetic marker '{marker}' was not emitted at source.")
        next_checks.append("Verify source audit logging configuration and test event generator.")

    # 2. Pipeline Routing Stage (Cribl Stream)
    cribl_data = evidence_files.get("cribl_route")
    if cribl_data and marker in json.dumps(cribl_data):
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
                details={"reason": "Event was filtered out or dropped in Cribl route pipeline."},
            ))
            diagnostics.append("Cribl Stream pipeline dropped or filtered out the synthetic marker event.")
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
            details={"reason": f"Marker '{marker}' was not observed in Cribl route metrics or stream buffers."},
        ))
        diagnostics.append("Event did not traverse Cribl Stream pipeline.")
        next_checks.append("Check Cribl Stream receiver health and worker node connectivity.")

    # 3. Destination Indexing Stage (Splunk Index or Sentinel Table)
    dest_data = evidence_files.get("destination_indexing")
    dest_component = "Splunk HEC / Indexer" if manifest.pipeline_route == "cribl_to_splunk" else "Log Analytics Workspace"
    dest_indexed = False
    if dest_data and marker in json.dumps(dest_data):
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
            details={"reason": f"Event containing marker '{marker}' was not found in destination index/table."},
        ))
        diagnostics.append(f"Event failed to reach destination {dest_component}.")
        next_checks.append("Verify destination credentials, HEC token, or Data Collection Rule permissions.")

    # 4. Query Evaluation Stage
    query_data = evidence_files.get("query_evaluation")
    rule_name = manifest.detection_rule.get("rule_name", "Detection Rule")
    query_matched = False
    if query_data and marker in json.dumps(query_data):
        matched_count = query_data.get("matched_count", 0)
        query_matched = matched_count > 0
        ts = query_data.get("evaluation_time", "")
        if query_matched:
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
                details={"reason": "Rule executed against table/index but query returned 0 matching rows."},
            ))
            diagnostics.append(f"Detection rule '{rule_name}' ran but did not match the indexed marker event.")
            next_checks.append("Review detection rule KQL/SPL query logic, time bounds, and threshold settings.")
    else:
        stages.append(StageObservation(
            stage_name="query_evaluation",
            status="missing",
            component=f"{rule_name} (Scheduled Query)",
            evidence_id="MISSING",
            details={"reason": "No execution record found for scheduled detection rule."},
        ))
        diagnostics.append(f"Scheduled detection query '{rule_name}' did not execute.")
        next_checks.append("Check SIEM scheduled search / analytics rule status and schedule interval.")

    # 5. Alert / Incident Creation Stage
    alert_data = evidence_files.get("alert_creation")
    alert_component = "Splunk Notable Event" if manifest.pipeline_route == "cribl_to_splunk" else "Sentinel Incident"
    alert_created = False
    if alert_data and marker in json.dumps(alert_data):
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
            details={"reason": "No security alert or incident was generated."},
        ))
        if dest_indexed and not alert_created:
            diagnostics.append("Marker was received and indexed at destination, but the detection rule did not create an alert.")
            next_checks.append("Check alert creation suppression rules, throttling window, and grouping settings.")

    # Calculate Summary Metrics
    observed_count = sum(1 for s in stages if s.status == "observed")
    missing_count = sum(1 for s in stages if s.status == "missing")
    unresolved_count = sum(1 for s in stages if s.status == "unresolved")

    # Pipeline health classification
    if observed_count == len(stages):
        health = "healthy"
    elif dest_indexed and not alert_created:
        health = "degraded"
    else:
        health = "broken"

    # Compute latency between first and last observed timestamps
    timestamps = [
        _parse_iso(s.timestamp) for s in stages
        if s.status == "observed" and s.timestamp and _parse_iso(s.timestamp) is not None
    ]
    total_latency = 0.0
    if len(timestamps) >= 2:
        total_latency = round((max(timestamps) - min(timestamps)).total_seconds(), 2)

    return {
        "schema_version": "cops.proof-report/v1",
        "report_id": f"REPORT-PROOF-{manifest.run_id}",
        "run_id": manifest.run_id,
        "synthetic_marker": marker,
        "route_type": manifest.pipeline_route,
        "evaluated_at": datetime.now().isoformat() + "Z",
        "pipeline_health": health,
        "summary": {
            "total_expected_stages": len(stages),
            "observed_stages_count": observed_count,
            "missing_stages_count": missing_count,
            "unresolved_stages_count": unresolved_count,
            "total_latency_seconds": total_latency,
            "detection_fired": alert_created,
        },
        "stages_breakdown": [s.to_dict() for s in stages],
        "diagnostics": diagnostics if diagnostics else ["All pipeline stages verified. Event flowed end-to-end and detection fired successfully."],
        "next_recommended_checks": next_checks if next_checks else ["Pipeline healthy. Maintain continuous synthetic heartbeat monitoring."],
        "privacy_statement": (
            "Proof packs contain synthetic markers and operational telemetry only. "
            "All sensitive credentials, tokens, and personal identifiers have been scrubbed. "
            f"Evidence retention complies with the {manifest.evidence_capture_policy.get('retention_days', 30)}-day run policy."
        ),
    }
