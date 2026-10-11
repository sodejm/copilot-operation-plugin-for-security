"""Markdown and JSON report formatters for Telemetry Proof Packs."""

from __future__ import annotations

import json
from typing import Any


def render_json_report(report_data: dict[str, Any]) -> str:
    """Render structured report as formatted JSON."""
    return json.dumps(report_data, indent=2) + "\n"


def render_markdown_report(report_data: dict[str, Any]) -> str:
    """Render human-friendly Markdown proof report."""
    run_id = report_data["run_id"]
    marker = report_data["synthetic_marker"]
    health = report_data["pipeline_health"].upper()
    summary = report_data["summary"]
    stages = report_data["stages_breakdown"]
    diag = report_data["diagnostics"]
    recs = report_data["next_recommended_checks"]

    status_badge = {
        "HEALTHY": "**HEALTHY (ALL STAGES OBSERVED)**",
        "DEGRADED": "**DEGRADED (DESTINATION MARKER FOUND; TRACE INCOMPLETE)**",
        "BROKEN": "**BROKEN (NO DESTINATION MARKER EVIDENCE)**",
    }.get(health, health)

    lines = [
        f"# Telemetry-to-Detection Proof Pack: {run_id}",
        "",
        "> [!IMPORTANT]",
        f"> Compares supplied records for synthetic test marker **`{marker}`** across five expected stages.",
        "> Correlates supplied evidence; missing records or ambiguous matches require operator investigation.",
        "",
        "## Pipeline Verification Summary",
        "",
        f"- **Run ID**: `{run_id}`",
        f"- **Synthetic Test Marker**: `{marker}`",
        f"- **Pipeline Route**: `{report_data['route_type']}`",
        f"- **Pipeline Status**: {status_badge}",
        f"- **Alert Record Observed**: `{'YES' if summary['detection_fired'] else 'NO'}`",
        f"- **Observed Stages**: {summary['observed_stages_count']} / {summary['total_expected_stages']}",
        f"- **First-to-Last Observed Stage Interval**: {summary['total_latency_seconds']}s",
        "",
        "## Stage-by-Stage Proof Trace",
        "",
        "| Stage | Status | Component | Timestamp | Evidence ID | Evidence SHA-256 | Stage Details |",
        "| :--- | :---: | :--- | :--- | :--- | :--- | :--- |",
    ]

    status_icons = {
        "observed": "OBSERVED",
        "missing": "**MISSING**",
        "unresolved": "**UNRESOLVED**",
    }

    for s in stages:
        st_lbl = status_icons.get(s["status"], s["status"])
        ts_str = s.get("timestamp", "—")
        ev_id = s.get("evidence_id", "—")
        evidence_hash = s.get("raw_evidence_hash") or "—"
        detail_items = s.get("details", {})
        det_str = "; ".join(f"{k}={v}" for k, v in detail_items.items()) if detail_items else "No details supplied"
        lines.append(f"| `{s['stage_name']}` | {st_lbl} | {s['component']} | {ts_str} | `{ev_id}` | `{evidence_hash}` | {det_str} |")

    lines.append("")
    lines.append("## Diagnostic Findings")
    lines.append("")
    for d in diag:
        lines.append(f"- {d}")

    lines.append("")
    lines.append("## Recommended Operator Actions")
    lines.append("")
    for r in recs:
        lines.append(f"- {r}")

    lines.append("")
    lines.append("## Privacy & Compliance")
    lines.append("")
    lines.append(f"> {report_data.get('privacy_statement', '')}")
    lines.append("")

    return "\n".join(lines)
