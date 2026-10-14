"""Generate human-friendly Markdown and content-addressed JSON review reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .models import EntraError, IdentityGraph, ReviewHypothesis
from .validation import validate_export_metadata, validate_report_artifact


def build_report_summary(graph: IdentityGraph, hypotheses: list[ReviewHypothesis]) -> dict[str, int]:
    """Compute summary counts for the report header."""
    counts = {
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "human_users": sum(1 for n in graph.nodes.values() if n.node_type == "user"),
        "service_principals": sum(1 for n in graph.nodes.values() if n.node_type == "service_principal"),
        "managed_identities": sum(1 for n in graph.nodes.values() if n.node_type == "managed_identity"),
        "agent_blueprints": sum(1 for n in graph.nodes.values() if n.node_type == "agent_blueprint"),
        "agent_identities": sum(1 for n in graph.nodes.values() if n.node_type == "agent_identity"),
        "critical_hypotheses": sum(1 for h in hypotheses if h.severity == "critical"),
        "high_hypotheses": sum(1 for h in hypotheses if h.severity == "high"),
    }
    return counts


def render_json_report(graph: IdentityGraph, hypotheses: list[ReviewHypothesis]) -> dict[str, Any]:
    """Construct typed dictionary matching report.v2.schema.json."""
    validate_export_metadata(graph)
    summary = build_report_summary(graph, hypotheses)
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    report_hypotheses = []
    edges_by_id = {edge.edge_id: edge for edge in graph.edges}
    for hypothesis in hypotheses:
        sources: set[str] = set()
        principal = graph.nodes.get(hypothesis.principal_id)
        if principal is None or graph.node_evidence(principal)[0] != "fresh":
            raise EntraError(f"hypothesis '{hypothesis.hypothesis_id}' has no fresh principal")
        if principal.evidence_source:
            sources.add(principal.evidence_source)
        for edge_id in hypothesis.supporting_edges:
            edge = edges_by_id.get(edge_id)
            if edge is None or graph.edge_evidence(edge)[0] != "fresh":
                raise EntraError(f"hypothesis '{hypothesis.hypothesis_id}' has a non-fresh edge")
            sources.update(edge.evidence_sources)
            for node_id in (edge.source_id, edge.target_id):
                endpoint = graph.nodes[node_id]
                if endpoint.evidence_source:
                    sources.add(endpoint.evidence_source)
        if hypothesis.category == "agent_privilege_mismatch":
            blueprint_id = str(principal.properties.get("blueprint_id", ""))
            blueprint = graph.nodes.get(blueprint_id)
            if blueprint is None or graph.node_evidence(blueprint)[0] != "fresh":
                raise EntraError(f"hypothesis '{hypothesis.hypothesis_id}' has no fresh blueprint")
            if blueprint.evidence_source:
                sources.add(blueprint.evidence_source)
        report_hypotheses.append(
            {
                **hypothesis.to_dict(),
                "evidence_status": "fresh",
                "evidence_sources": sorted(sources),
            }
        )
    document = {
        "schema_version": "entra.identity-report/v2",
        "tenant_id": graph.tenant_id,
        "analyzed_at": now_iso,
        "assessed_at": graph.assessed_at,
        "max_age_hours": graph.max_age_hours,
        "source_coverage": graph.source_coverage,
        "summary": summary,
        "hypotheses": report_hypotheses,
    }
    validate_report_artifact(document)
    return document


def render_markdown_report(graph: IdentityGraph, hypotheses: list[ReviewHypothesis]) -> str:
    """Render human-friendly Markdown report."""
    # Use the same freshness and provenance checks as the JSON artifact before
    # showing caller-supplied hypotheses as current review items.
    summary = render_json_report(graph, hypotheses)["summary"]
    unknown_sources = [source_id for source_id, item in graph.source_coverage.items() if item["status"] != "fresh"]

    def safe_text(value: Any) -> str:
        """Render export-derived text without Markdown structure or raw HTML."""
        flattened = " ".join("".join(char if char.isprintable() else " " for char in str(value)).split())
        special = r"\`*_{}[]()#+-.!|><&~"
        return "".join(f"&#{ord(char)};" if char in special else char for char in flattened)

    def cell(value: Any) -> str:
        """Keep an optional value inside one Markdown table cell."""
        if value is None:
            return "—"
        return safe_text(value)

    lines: list[str] = [
        "# Entra Identity & Agent Exposure Review",
        "",
        "> [!IMPORTANT]",
        "> Identity graph relationships represent **structural entitlement reachability and access potential**.",
        "> They do not prove active attacker exploitation or unauthorized token acquisition.",
        "> Review hypotheses indicate configurations warranting security verification.",
        "",
        "## Evidence Coverage & Freshness",
        "",
        f"- **Assessment time (UTC)**: {cell(graph.assessed_at)}",
        f"- **Maximum export age**: {graph.max_age_hours} hours; future timestamps are unknown.",
        "- Only present, hash-verified, full exports at or before the assessment time and within the age limit support current paths.",
        "- Paths from stale, missing, incomplete, or invalid exports remain modeled for inspection but are marked unknown and excluded from current hypotheses.",
        "",
    ]

    if graph.source_coverage:
        lines.extend(
            [
                "| Source | Status | Reason | Exported at | Completeness | Manifest path | SHA-256 |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for source_id, item in graph.source_coverage.items():
            lines.append(
                f"| {cell(source_id)} | {cell(item['status'])} | {cell(item['reason'])} "
                f"| {cell(item['exported_at'])} | {cell(item['completeness'])} "
                f"| {cell(item['path'])} | {cell(item['sha256'])} |"
            )
        lines.append("")
    if unknown_sources:
        lines.extend(
            [
                "Evidence coverage is unknown for: " + ", ".join(cell(s) for s in unknown_sources) + ".",
                "Refresh or complete those exports before interpreting their paths as current access.",
                "",
            ]
        )
    elif not graph.source_coverage:
        lines.extend(
            [
                "Evidence coverage is missing; modeled paths cannot support current access hypotheses.",
                "",
            ]
        )

    lines.extend(
        [
            "## Tenant & Identity Inventory",
            "",
            f"- **Tenant ID**: {safe_text(graph.tenant_id)}",
            f"- **Total Modeled Entities**: {summary['total_nodes']}",
            f"- **Total Relationships / Entitlements**: {summary['total_edges']}",
            "- Counts include modeled records with unknown freshness; use the coverage table for current evidence.",
            "",
            "| Entity Type | Count | Description |",
            "| :--- | :--- | :--- |",
            f"| **Human Users** | {summary['human_users']} | Direct member and B2B guest accounts |",
            f"| **Service Principals** | {summary['service_principals']} | Enterprise applications and API principals |",
            f"| **Managed Identities** | {summary['managed_identities']} | Workload identities for Azure services |",
            f"| **Agent Blueprints** | {summary['agent_blueprints']} | Declarative Foundry / Agent ID template specifications |",
            f"| **Agent Identities** | {summary['agent_identities']} | Instantiated runtime Agent ID principals |",
            "",
            "## Prioritized Review Hypotheses",
            "",
            f"- **Critical Findings**: {summary['critical_hypotheses']}",
            f"- **High Findings**: {summary['high_hypotheses']}",
            f"- **Total Review Items**: {len(hypotheses)}",
            "",
        ]
    )

    if not hypotheses:
        if unknown_sources or not graph.source_coverage:
            lines.append(
                "No current exposure hypotheses are supported by the available fresh evidence; unknown paths still require review.\n"
            )
        else:
            lines.append("No exposure hypotheses identified in this export scope.\n")
    else:
        lines.extend(
            [
                "| ID | Severity | Category | Principal | Description | Action |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for h in hypotheses:
            severity = safe_text(h.severity.upper())
            sev_badge = f"**{severity}**" if h.severity in ("critical", "high") else severity.title()
            row = (
                f"| {safe_text(h.hypothesis_id)} | {sev_badge} | {safe_text(h.category)} "
                f"| {safe_text(h.principal_name)} ({safe_text(h.principal_type)}) "
                f"| {safe_text(h.description)} | {safe_text(h.recommended_action)} |"
            )
            lines.append(row)

        lines.extend(["", "### Detailed Hypothesis Traces", ""])
        for h in hypotheses:
            lines.extend(
                [
                    f"#### [{safe_text(h.severity.upper())}] {safe_text(h.hypothesis_id)}: {safe_text(h.principal_name)}",
                    f"- **Category**: {safe_text(h.category)}",
                    f"- **Principal**: {safe_text(h.principal_id)} ({safe_text(h.principal_type)})",
                    f"- **Description**: {safe_text(h.description)}",
                    f"- **Supporting Edges**: {', '.join(safe_text(e) for e in h.supporting_edges) or 'None cited'}",
                    f"- **Missing Telemetry / Evidence**: {', '.join(safe_text(e) for e in h.missing_evidence) or 'None recorded'}",
                    f"- **Recommended Remediation**: {safe_text(h.recommended_action)}",
                    "",
                ]
            )

    return "\n".join(lines)
