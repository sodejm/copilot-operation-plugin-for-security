"""Generate human-friendly Markdown and content-addressed JSON review reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import IdentityGraph, ReviewHypothesis


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
    """Construct typed dictionary matching report.schema.json."""
    summary = build_report_summary(graph, hypotheses)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
      "schema_version": "entra.identity-report/v1",
      "tenant_id": graph.tenant_id,
      "analyzed_at": now_iso,
      "summary": summary,
      "hypotheses": [h.to_dict() for h in hypotheses],
    }


def render_markdown_report(graph: IdentityGraph, hypotheses: list[ReviewHypothesis]) -> str:
    """Render human-friendly Markdown report."""
    summary = build_report_summary(graph, hypotheses)

    lines: list[str] = [
        "# Entra Identity & Agent Exposure Review",
        "",
        "> [!IMPORTANT]",
        "> Identity graph relationships represent **structural entitlement reachability and access potential**.",
        "> They do not prove active attacker exploitation or unauthorized token acquisition.",
        "> Review hypotheses indicate configurations warranting security verification.",
        "",
        "## Tenant & Identity Inventory",
        "",
        f"- **Tenant ID**: `{graph.tenant_id}`",
        f"- **Total Modeled Entities**: {summary['total_nodes']}",
        f"- **Total Relationships / Entitlements**: {summary['total_edges']}",
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

    if not hypotheses:
        lines.append("No exposure hypotheses identified in this export scope.\n")
    else:
        lines.extend([
            "| ID | Severity | Category | Principal | Description | Action |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for h in hypotheses:
            sev_badge = f"**{h.severity.upper()}**" if h.severity in ("critical", "high") else h.severity.title()
            row = (
                f"| `{h.hypothesis_id}` | {sev_badge} | `{h.category}` "
                f"| `{h.principal_name}` ({h.principal_type}) | {h.description} | {h.recommended_action} |"
            )
            lines.append(row)

        lines.extend(["", "### Detailed Hypothesis Traces", ""])
        for h in hypotheses:
            lines.extend([
                f"#### [{h.severity.upper()}] {h.hypothesis_id}: {h.principal_name}",
                f"- **Category**: `{h.category}`",
                f"- **Principal**: `{h.principal_id}` ({h.principal_type})",
                f"- **Description**: {h.description}",
                f"- **Supporting Edges**: {', '.join(f'`{e}`' for e in h.supporting_edges) or 'None cited'}",
                f"- **Missing Telemetry / Evidence**: {', '.join(h.missing_evidence) or 'None recorded'}",
                f"- **Recommended Remediation**: {h.recommended_action}",
                "",
            ])

    return "\n".join(lines)
