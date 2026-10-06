"""Deterministic reference evaluator for Sentinel KQL and Splunk SPL detections."""

from __future__ import annotations

from typing import Any

from .models import CaseResult, FixtureCase, FixtureSuite, Rule
from .static_analysis import analyze_rule_dependencies


def _evaluate_event_predicate(event: dict[str, Any], rule: Rule) -> bool:
    """Evaluate whether an event satisfies the rule logic predicate."""
    # Check if any required field is completely missing
    for req in rule.required_fields:
        if req not in event:
            return False

    # 1. KQL evaluation
    if rule.platform == "sentinel_kql":
        # Check specific rule logic templates
        if rule.rule_id == "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN":
            res_type = event.get("ResultType")
            app_name = event.get("AppDisplayName", "")
            risk = str(event.get("RiskLevelDuringSignIn", "")).lower()
            ip = str(event.get("IPAddress", ""))

            # Logic: ResultType == 0 and AppDisplayName == 'Azure Portal' and (RiskLevelDuringSignIn in ('high', 'medium') or IP is external)
            if res_type == 0 and app_name == "Azure Portal":
                if risk in ("high", "medium"):
                    return True
                # Check if IP is external (not 10.x and not 192.168.x)
                if not (ip.startswith("10.") or ip.startswith("192.168.")):
                    return True
            return False

        # Generic KQL evaluation fallback
        query = rule.logic.get("query_template", "")
        return _generic_evaluate(event, query)

    # 2. Splunk SPL evaluation
    elif rule.platform == "splunk_spl":
        if rule.rule_id == "RULE-SPL-DEFENDER-POWERSHELL-EXEC":
            event_code = event.get("EventCode")
            script = str(event.get("ScriptBlockText", "")).lower()

            if str(event_code) == "4104":
                suspicious_patterns = ["-encodedcommand", "downloadstring", "iex", "invoke-expression"]
                if any(p in script for p in suspicious_patterns):
                    return True
            return False

        # Generic SPL evaluation fallback
        query = rule.logic.get("query_template", "")
        return _generic_evaluate(event, query)

    return False


def _generic_evaluate(event: dict[str, Any], query: str) -> bool:
    """Simple generic evaluator checking field value patterns."""
    q_lower = query.lower()
    for k, v in event.items():
        v_str = str(v).lower()
        if k.lower() in q_lower and v_str in q_lower:
            return True
    return False


def evaluate_fixture_case(case: FixtureCase, rule: Rule) -> CaseResult:
    """Evaluate all events in a single fixture case."""
    missing_fields_in_case = set()
    for req in rule.required_fields:
        for ev in case.events:
            if req not in ev:
                missing_fields_in_case.add(req)

    # Check if any event matches the rule predicate
    matched = any(_evaluate_event_predicate(ev, rule) for ev in case.events)

    # Classification
    if missing_fields_in_case:
        outcome = "missing_field_error"
        details = f"Required field(s) missing from telemetry events: {sorted(missing_fields_in_case)}"
    elif case.expected_match and matched:
        outcome = "true_positive" if case.label == "positive" else "boundary_handled"
        details = "Rule logic triggered as expected on target telemetry."
    elif not case.expected_match and not matched:
        outcome = "true_negative" if case.label == "negative" else "boundary_handled"
        details = "Rule logic correctly avoided benign or unmatching telemetry."
    elif case.expected_match and not matched:
        outcome = "false_negative"
        details = "Rule missed expected positive attack signal."
    else:
        # not case.expected_match and matched
        outcome = "false_positive"
        details = "Rule incorrectly matched benign or non-malicious event (noisy detection)."

    return CaseResult(
        case_id=case.case_id,
        label=case.label,
        expected_match=case.expected_match,
        actual_match=matched,
        outcome_classification=outcome,
        details=details,
        missing_fields=tuple(sorted(missing_fields_in_case)),
    )


def evaluate_rule_suite(rule: Rule, suite: FixtureSuite, environment: str = "offline_reference_evaluator") -> dict[str, Any]:
    """Evaluate a complete fixture suite against a rule."""
    static_checks = analyze_rule_dependencies(rule, list(suite.cases))

    case_results = [evaluate_fixture_case(case, rule) for case in suite.cases]

    # Metrics
    tp = sum(1 for r in case_results if r.outcome_classification in ("true_positive", "boundary_handled") and r.expected_match)
    fp = sum(1 for r in case_results if r.outcome_classification == "false_positive")
    tn = sum(1 for r in case_results if r.outcome_classification in ("true_negative", "boundary_handled") and not r.expected_match)
    fn = sum(1 for r in case_results if r.outcome_classification == "false_negative" or (r.outcome_classification == "missing_field_error" and r.expected_match))

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0

    recommendations: list[str] = []
    if fp > 0:
        recommendations.append(
            f"Rule generated {fp} false positive(s). Add filter exclusions or tighten entity/role scopes."
        )
    if fn > 0:
        recommendations.append(
            f"Rule missed {fn} target positive case(s). Review join conditions or required field assumptions."
        )
    if static_checks["missing_fields"]:
        recommendations.append(
            f"Telemetry schema drift: Missing required field(s) {static_checks['missing_fields']}. Update collection pipeline or declare fields optional."
        )
    if not recommendations:
        recommendations.append("All labeled fixture cases evaluated cleanly. Rule is ready for staging deployment.")

    return {
        "schema_version": "cops.detection-quality-report/v1",
        "report_id": f"REPORT-DQ-{rule.rule_id}",
        "evaluated_at": "2026-10-01T00:00:00Z",
        "rule": {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "platform": rule.platform,
            "version": rule.version,
        },
        "evaluation_environment": environment,
        "disclaimer": (
            "Reference-evaluator output indicates fixture precision/recall only and does not establish "
            "production scheduled alert firing."
        ),
        "metrics": {
            "total_cases": len(case_results),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision_on_labeled_fixtures": precision,
            "recall_on_labeled_fixtures": recall,
        },
        "static_checks": static_checks,
        "case_results": [r.to_dict() for r in case_results],
        "recommendations": recommendations,
    }
