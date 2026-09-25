"""Generate a deterministic readable projection of the typed JSON report."""

from __future__ import annotations

import json
from html import escape
from typing import Any


def label(value: Any) -> str:
    return escape(json.dumps(value, ensure_ascii=False), quote=True)


def markdown(report: dict[str, Any]) -> str:
    lines = ["# Offline attack-path analysis", "", "## Evidence boundary", "",
             "These are conditional potential routes. A sourced graph relationship does not prove exploitability or attacker activity.",
             "The source coverage statement is declared by the input and is not independently verified.", "",
             "## Run and crown jewels", "", f"- Run: {label(report['run']['run_id'])}",
             f"- Input SHA-256: {label(report['run']['input_sha256'])}"]
    for crown in report["context"]["crown_jewels"]:
        lines.append(f"- Crown jewel: {label(crown['asset_ref'])} ({label(crown['name'])}); priority {label(crown['priority'])}")
    lines += ["", "## Source coverage and reconciliation", ""]
    for item in report["coverage"]:
        lines.append(f"- {label(item['source_id'])}: declared {label(item['declared_coverage'])}; completeness unverified")
    lines.append(f"- Raw {report['reconciliation']['raw']}; accepted {report['reconciliation']['accepted']}; quarantined {report['reconciliation']['quarantined']}; rejected {report['reconciliation']['rejected']}")
    for heading, key in (("Supported structural paths", "supported_paths"), ("Candidate paths", "candidate_paths")):
        lines += ["", f"## {heading}", ""]
        if not report[key]:
            lines.append("None in this export and scope.")
        for path in report[key]:
            lines += [f"### {label(path['path_id'])}", "",
                      f"- Finding: {label(path['start_finding'])}; target: {label(path['target'])}",
                      f"- Conditional premise: {label(path['premise'])}",
                      f"- Evidence refs: {', '.join(label(x) for x in path['evidence_refs'])}",
                      f"- Evidence-support confidence: {label(path['confidence'])}",
                      f"- Evidenced assets on supported path: {path['blast_radius']['evidenced_asset_count']}; services with observed direct dependencies on those assets: {path['blast_radius']['evidenced_service_count']}",
                      f"- Potential CIA: {', '.join(path['impact']['potential_cia']) or 'none established'}; business rating: unrated"]
            for step in path["steps"]:
                lines.append(f"- Step {label(step['edge_id'])}: {label(step['from'])} → {label(step['to'])}; relation {label(step['relation'])}; capability {label(step['postcondition'])}; sources {', '.join(label(ref) for ref in step['supporting_evidence_refs'])}")
            for gap in path["gaps"]:
                lines.append(f"- Gap: {label(gap)}")
    lines += ["", "## ATT&CK and Attack Flow", "",
              "No technique IDs or Attack Flow serialization: approved, pinned local reference data is pending.",
              "", "## Proposed actions", ""]
    if not report["actions"]:
        lines.append("No route-specific actions generated.")
    for action in report["actions"]:
        lines += [f"- {label(action['action_id'])} for {label(action['path_id'])}: {label(action['proposal'])}",
                  f"  - Validation: {label(action['validation'])}", f"  - Monitoring: {label(action['monitoring'])}",
                  f"  - Investigation: {label(action['investigation'])}",
                  f"  - Evidence refs: {', '.join(label(x) for x in action['evidence_refs'])}; owner and closure evidence pending"]
    lines += ["", "## Assumptions, gaps, and human review", ""]
    for field in ("assumptions", "evidence_gaps", "alternative_interpretations", "human_review"):
        lines.append(f"- {field}: {', '.join(label(x) for x in report[field]) or 'none recorded'}")
    lines += ["", "## Exclusions and source index", ""]
    for item in report["quarantine"]:
        lines.append(f"- Quarantined {label(item['source']['source_id'])}{label(item['source']['record_pointer'])}: {label(item['reason'])}")
    for item in report["graph_exclusions"]:
        lines.append(f"- Graph exclusion: {label(item)}")
    for fact in report["evidence"]:
        src = fact["source"]
        lines.append(f"- {label(fact['evidence_id'])}: {label(src['source_id'])}, SHA-256 {label(src['file_sha256'])}, pointer {label(src['record_pointer'])}; class {label(fact['class'])}")
    lines += ["", "## Gate results and reproducibility", ""]
    for gate, result in sorted(report["gate_results"].items()):
        lines.append(f"- {gate}: {result}")
    lines.append(f"- Rule version: {label(report['run']['rule_version'])}; SHA-256: {label(report['run']['rule_sha256'])}; tool version: {label(report['run']['tool_version'])}")
    for profile, fingerprint in sorted(report["run"]["profile_sha256"].items()):
        lines.append(f"- Profile {label(profile)} SHA-256: {label(fingerprint)}")
    return "\n".join(lines) + "\n"
