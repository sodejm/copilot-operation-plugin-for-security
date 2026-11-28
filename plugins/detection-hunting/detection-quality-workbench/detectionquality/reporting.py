"""Markdown and JSON report formatting for detection quality evaluations."""

from __future__ import annotations

import json
from typing import Any


def render_json_report(report_data: dict[str, Any]) -> str:
    """Render structured report as formatted JSON."""
    return json.dumps(report_data, indent=2) + "\n"


def render_markdown_report(report_data: dict[str, Any]) -> str:
    """Render human-friendly Markdown quality report."""
    rule = report_data["rule"]
    metrics = report_data["metrics"]
    static = report_data["static_checks"]
    cases = report_data["case_results"]
    recs = report_data["recommendations"]
    precision = metrics["precision_on_labeled_fixtures"]
    recall = metrics["recall_on_labeled_fixtures"]
    precision_label = "N/A (schema errors)" if precision is None else f"{precision * 100:.1f}%"
    recall_label = "N/A (schema errors)" if recall is None else f"{recall * 100:.1f}%"

    lines = [
        f"# Detection Quality & Regression Report: {rule['rule_id']}",
        "",
        "> [!IMPORTANT]",
        f"> {report_data.get('disclaimer', '')}",
        "",
        "## Rule Overview",
        "",
        f"- **Rule ID**: `{rule['rule_id']}`",
        f"- **Name**: {rule['name']}",
        f"- **Platform**: `{rule['platform']}`",
        f"- **Version**: `{rule['version']}`",
        f"- **Evaluation Environment**: `{report_data.get('evaluation_environment', 'offline_reference_evaluator')}`",
        "",
        "## Quality Metrics on Labeled Fixtures",
        "",
        "| Metric | Value | Meaning |",
        "| :--- | :--- | :--- |",
        f"| **Total Test Cases** | {metrics['total_cases']} | Total labeled scenario cases in test suite |",
        f"| **Evaluated Cases** | {metrics['evaluated_cases']} | Cases classified as TP, FP, TN, or FN |",
        f"| **Schema Error Cases** | {metrics['schema_error_cases']} | Cases missing required telemetry fields; excluded from the confusion matrix |",
        f"| **True Positives (TP)** | {metrics['true_positives']} | Target malicious attacks correctly caught |",
        f"| **False Positives (FP)** | {metrics['false_positives']} | Benign baseline activity incorrectly flagged (noisy) |",
        f"| **True Negatives (TN)** | {metrics['true_negatives']} | Benign activity correctly ignored |",
        f"| **False Negatives (FN)** | {metrics['false_negatives']} | Target attacks missed by rule logic |",
        f"| **Fixture Precision** | {precision_label} | Ratio of true attacks among all rule alerts |",
        f"| **Fixture Recall** | {recall_label} | Ratio of detected attacks among all actual attacks |",
        "",
        "## Static Dependency & Schema Checks",
        "",
        f"- **All Required Fields Present**: `{'YES' if static['required_fields_present'] else 'NO'}`",
    ]

    if static["missing_fields"]:
        lines.append(f"- **Missing Required Fields**: `{', '.join(static['missing_fields'])}`")
    else:
        lines.append("- **Missing Required Fields**: *None (all declared telemetry fields supplied)*")

    lines.append(f"- **Schema Drift Detected**: `{'YES' if static['schema_drift_detected'] else 'NO'}`")
    lines.append("")
    lines.append("## Labeled Scenario Results")
    lines.append("")
    lines.append("| Case ID | Label | Expected | Match | Classification | Details |")
    lines.append("| :--- | :--- | :---: | :---: | :--- | :--- |")

    class_labels = {
        "true_positive": "True Positive (Caught)",
        "true_negative": "True Negative (Passed)",
        "false_positive": "**FALSE POSITIVE (Noisy)**",
        "false_negative": "**FALSE NEGATIVE (Missed)**",
        "missing_field_error": "**MISSING FIELD ERROR**",
        "boundary_handled": "Boundary Handled",
    }

    for c in cases:
        exp_icon = "Match" if c["expected_match"] else "No Match"
        act_icon = "Match" if c["actual_match"] else "No Match"
        lbl_str = class_labels.get(c["outcome_classification"], c["outcome_classification"])
        lines.append(f"| `{c['case_id']}` | `{c['label']}` | {exp_icon} | {act_icon} | {lbl_str} | {c['details']} |")

    lines.append("")
    lines.append("## Engineering Recommendations")
    lines.append("")
    for r in recs:
        lines.append(f"- {r}")

    lines.append("")
    return "\n".join(lines)
