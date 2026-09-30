"""Format JSON and Markdown review reports for Foundry adversarial agent testing."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import ExecutionEvent, Scenario


def render_json_report(
    scenarios: list[Scenario],
    events: list[ExecutionEvent],
    target_agent: dict[str, str],
    environment: str,
) -> dict[str, Any]:
    """Render findings as structured JSON matching schema."""
    model_only = sum(1 for e in events if e.outcome_level == "model_output_only")
    attempted = sum(1 for e in events if e.attempted_tool is not None)
    denied = sum(1 for e in events if e.outcome_level == "denied_tool_call")
    executed = sum(1 for e in events if e.outcome_level == "executed_mock_effect")

    return {
        "schema_version": "foundry.review-report/v1",
        "report_id": f"REPORT-FOUNDRY-{int(datetime.now(timezone.utc).timestamp())}",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "target_agent": target_agent,
        "environment": environment,
        "summary": {
            "total_scenarios": len(events),
            "model_output_only_count": model_only,
            "attempted_tool_call_count": attempted,
            "denied_tool_call_count": denied,
            "executed_mock_effect_count": executed,
        },
        "findings": [e.to_dict() for e in events],
    }


def render_markdown_report(
    scenarios: list[Scenario],
    events: list[ExecutionEvent],
    target_agent: dict[str, str],
    environment: str,
) -> str:
    """Render findings as human-friendly Markdown review report."""
    model_only = sum(1 for e in events if e.outcome_level == "model_output_only")
    attempted = sum(1 for e in events if e.attempted_tool is not None)
    denied = sum(1 for e in events if e.outcome_level == "denied_tool_call")
    executed = sum(1 for e in events if e.outcome_level == "executed_mock_effect")

    lines = [
        "# Microsoft Foundry Adversarial Agent Review Report",
        "",
        "> [!IMPORTANT]",
        "> Adversarial evaluations test **model prompt-injection resistance and independent authorization enforcement**.",
        "> A generated unsafe response is **not** an executed compromise. A secure architecture relies on",
        "> independent policy gates preventing untrusted execution even when models are manipulated.",
        "",
        "## Evaluation Summary",
        "",
        f"- **Target Agent**: `{target_agent.get('agent_name', 'Unknown')}` (version: `{target_agent.get('agent_version', '1.0')}`, framework: `{target_agent.get('framework', 'Foundry')}`)",
        f"- **Test Environment**: `{environment}` (offline mock sandbox)",
        f"- **Total Scenarios Evaluated**: {len(events)}",
        f"- **Model Output Only (No Tool)**: {model_only}",
        f"- **Attempted Tool Calls**: {attempted}",
        f"- **Denied by Independent Gate**: {denied}",
        f"- **Executed Permitted Effects**: {executed}",
        "",
        "## Scenario Outcomes Overview",
        "",
        "| Scenario | Surface | Outcome Level | Gate Decision | Risk Summary |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    outcome_labels = {
        "model_output_only": "Model Output Only",
        "attempted_tool_call": "Attempted Tool Call",
        "denied_tool_call": "**DENIED (BLOCKED)**",
        "executed_mock_effect": "*Executed Mock Effect*",
    }

    decision_labels = {
        "allow": "`ALLOW`",
        "deny": "**`DENY`**",
        "not_applicable": "N/A",
    }

    for e in events:
        out_lbl = outcome_labels.get(e.outcome_level, e.outcome_level)
        dec_lbl = decision_labels.get(e.authorization_decision, e.authorization_decision)
        risk_short = (e.risk_assessment[:65] + "...") if len(e.risk_assessment) > 65 else e.risk_assessment
        lines.append(f"| `{e.scenario_id}` | `{e.surface}` | {out_lbl} | {dec_lbl} | {risk_short} |")

    lines.append("")
    lines.append("## Detailed Scenario Findings")
    lines.append("")

    for e in events:
        lines.append(f"### [{e.scenario_id}] {e.title}")
        lines.append(f"- **Trace ID**: `{e.trace_id}`")
        lines.append(f"- **Attacker Surface**: `{e.surface}`")
        lines.append(f"- **Outcome Level**: `{e.outcome_level}`")
        lines.append(f"- **Gate Decision**: `{e.authorization_decision}`")
        lines.append(f"- **Model Response Summary**: {e.model_response_summary}")
        lines.append(f"- **Risk Assessment**: {e.risk_assessment}")

        if e.attempted_tool:
            lines.append(f"- **Attempted Tool Call**: `{e.attempted_tool.get('tool_name')}` with arguments: `{e.attempted_tool.get('arguments')}`")

        if e.gate_denial_reason:
            lines.append(f"- **Gate Enforcement**: {e.gate_denial_reason}")

        if e.executed_side_effect:
            lines.append(f"- **Executed Mock Effect**: `{e.executed_side_effect.get('action')}` on `{e.executed_side_effect.get('target')}` (reversible: `{e.executed_side_effect.get('reversible')}`)")

        lines.append("- **Evidence Citations**:")
        for ev in e.evidence_citations:
            lines.append(f"  - {ev}")

        lines.append("")

    return "\n".join(lines)
