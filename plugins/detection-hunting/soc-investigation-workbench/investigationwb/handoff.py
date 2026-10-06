"""Immutable, reviewable case handoff report generation (Markdown and JSON).

Exports complete case scope, chronological timeline, entity ledger, hypothesis status,
coverage gaps, and prioritized next inquiries with owner-only permissions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .engine import Document, digest, hypothesis_status, next_steps, validate


def generate_handoff(case: Document) -> tuple[Document, str]:
    """Generate machine-readable handoff JSON dict and human-readable Markdown string."""
    validate(case)

    case_id = case["id"]
    snap_hash = digest(case)
    scope = case["scope"]
    hypo_stat = hypothesis_status(case)
    next_st = next_steps(case)

    # Sort evidence chronologically for timeline
    timeline_records = sorted(
        case["evidence"],
        key=lambda item: (item["event_time"], item["id"]),
    )

    completed_results = [
        {
            "result_id": r["id"],
            "step_id": r["step_id"],
            "outcome": r["outcome"],
            "coverage": r["coverage"],
            "evidence_count": len(r["evidence_ids"]),
        }
        for r in case["results"]
    ]

    coverage_gaps = [
        {
            "step_id": r["step_id"],
            "coverage": r["coverage"],
            "outcome": r["outcome"],
        }
        for r in case["results"]
        if r["coverage"] != "complete"
    ]

    step_map = {s["id"]: s for s in case["steps"]}
    ready_candidates = []
    for cand in next_st.get("candidates", []):
        step_id = cand["step_id"]
        step = step_map.get(step_id, {})
        ready_candidates.append({
            "step_id": step_id,
            "question": step.get("question", "Unknown"),
            "hunt_id": step.get("query", {}).get("hunt_id", "N/A"),
            "surface": step.get("query", {}).get("surface", "N/A"),
            "entities": step.get("query", {}).get("entities", []),
            "information_gain": cand.get("information_gain", 0),
            "urgency": cand.get("urgency", 0),
            "impact": cand.get("impact", 0),
            "cost": cand.get("cost", 1),
        })

    handoff_dict: Document = {
        "schema_version": 1,
        "case_id": case_id,
        "snapshot_hash": snap_hash,
        "scope": scope,
        "budget": case["budget"],
        "hypotheses": hypo_stat,
        "state": next_st.get("state", "ready"),
        "reason": next_st.get("reason"),
        "timeline": [
            {
                "time_utc": ev["event_time"],
                "evidence_id": ev["id"],
                "source": ev["source"],
                "entities": ev["entities"],
                "summary": ev["summary"],
                "assessments": ev["assessments"],
            }
            for ev in timeline_records
        ],
        "entities": case["entities"],
        "completed_results": completed_results,
        "coverage_gaps": coverage_gaps,
        "next_inquiries": ready_candidates,
        "limitations": [
            "Analyst assessments are not independently verified.",
            "Shared entities establish correlation and inquiry pivots, not confirmed causation.",
            "No automated response actions or live query validations have been executed.",
        ],
    }

    # Generate Human-Friendly Markdown
    lines = [
        f"# Incident Case Handoff: `{case_id}`",
        "",
        "## Executive Summary",
        "",
        "| Attribute | Value |",
        "| :--- | :--- |",
        f"| **Case ID** | `{case_id}` |",
        f"| **Snapshot Hash** | `{snap_hash}` |",
        f"| **Tenant** | `{scope['tenant']}` |",
        f"| **Workspace** | `{scope['workspace']}` |",
        f"| **Interval (UTC)** | `{scope['start']}` to `{scope['end']}` |",
        f"| **Planner State** | `{next_st.get('state', 'ready')}` (Reason: `{next_st.get('reason') or 'none'}`) |",
        f"| **Total Evidence Count** | {len(case['evidence'])} item(s) |",
        f"| **Completed Steps** | {len(case['results'])} step(s) |",
        "",
        "---",
        "",
        "## Competing Hypotheses Evaluation",
        "",
        "COPS maintains competing hypotheses to counter confirmation bias during triage:",
        "",
    ]

    for h in case["hypotheses"]:
        h_id = h["id"]
        stat = next((s for s in hypo_stat if s["id"] == h_id), {})
        status_label = stat.get("status", "unresolved").replace("_", " ").upper()
        supports_refs = ", ".join(stat.get("supports", [])) or "None"
        refutes_refs = ", ".join(stat.get("refutes", [])) or "None"

        lines.extend([
            f"### `{h_id}` ({h['kind'].capitalize()}) — **{status_label}**",
            f"> *\"{h['statement']}\"*",
            "",
            f"- **Supporting Evidence**: {supports_refs}",
            f"- **Refuting Evidence**: {refutes_refs}",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## Chronological Evidence Timeline",
        "",
        "| Time (UTC) | Evidence ID | Source | Entities | Observation Summary |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    for ev in timeline_records:
        ents = ", ".join(f"`{e}`" for e in ev["entities"])
        safe_summary = ev["summary"].replace("|", "\\|")
        lines.append(f"| `{ev['event_time']}` | `{ev['id']}` | `{ev['source']}` | {ents} | {safe_summary} |")

    lines.extend([
        "",
        "---",
        "",
        "## Recommended Next Inquiries (Next Shift Action Plan)",
        "",
    ])

    if ready_candidates:
        lines.extend([
            "The case engine has ranked the highest-gain next questions based on information gain, urgency, and cost:",
            "",
            "| Step ID | Recommended Hunt | Entities | Urgency | Gain | Question |",
            "| :--- | :--- | :--- | :---: | :---: | :--- |",
        ])
        for cand in ready_candidates:
            ents = ", ".join(f"`{e}`" for e in cand["entities"])
            lines.append(
                f"| `{cand['step_id']}` | `{cand['hunt_id']}` ({cand['surface']}) | {ents} | {cand['urgency']}/5 | {cand['information_gain']}/5 | {cand['question']} |"
            )
        lines.append("")
    else:
        lines.extend([
            "No candidate inquiries are currently ready to execute (plan exhausted, stopped on budget, or awaiting external inputs).",
            "",
        ])

    if coverage_gaps:
        lines.extend([
            "---",
            "",
            "## Coverage Gaps & Telemetry Blind Spots",
            "",
            "The following completed inquiries encountered missing or partial telemetry:",
            "",
            "| Step ID | Outcome | Coverage Level |",
            "| :--- | :--- | :--- |",
        ])
        for gap in coverage_gaps:
            lines.append(f"| `{gap['step_id']}` | `{gap['outcome']}` | `{gap['coverage']}` |")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## Operational Boundaries & Evidence Notices",
        "",
        "- **Advisory Decision Support**: This case handoff records structured observations and hypotheses. It is not an automated verdict or proof of compromise.",
        "- **Identity vs. Causation**: Co-occurring IP addresses or user accounts establish inquiry pivots, not confirmed adversary ownership.",
        "- **Zero Automated Mutation**: No remediation, host isolation, or user account modification has been triggered.",
        "",
    ])

    handoff_markdown = "\n".join(lines)
    return handoff_dict, handoff_markdown


def write_handoff(out_dir: Path, case: Document) -> dict[str, str]:
    """Exclusively write handoff.json and handoff.md with owner-only permissions."""
    handoff_dict, handoff_md = generate_handoff(case)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "handoff.json"
    md_path = out_dir / "handoff.md"

    encoded_json = (json.dumps(handoff_dict, indent=2, allow_nan=False) + "\n").encode("utf-8")
    encoded_md = (handoff_md + "\n").encode("utf-8")

    # Write JSON exclusively
    fd_json = os.open(json_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd_json, "wb") as stream:
            stream.write(encoded_json)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        json_path.unlink(missing_ok=True)
        raise

    # Write Markdown exclusively
    fd_md = os.open(md_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd_md, "wb") as stream:
            stream.write(encoded_md)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        md_path.unlink(missing_ok=True)
        raise

    return {
        "status": "written",
        "case_id": case["id"],
        "snapshot_hash": handoff_dict["snapshot_hash"],
        "json_path": str(json_path),
        "md_path": str(md_path),
    }
