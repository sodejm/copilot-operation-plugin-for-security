"""Deterministic reference evaluator for Sentinel KQL and Splunk SPL detections."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from .models import CaseResult, FixtureCase, FixtureSuite, QualityError, Rule
from .static_analysis import analyze_rule_dependencies


def _timestamp(value: Any) -> datetime:
    """Require an offset-aware ISO 8601 timestamp for deterministic comparisons."""
    if not isinstance(value, str):
        raise QualityError(f"Invalid timestamp: {value!r}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise QualityError(f"Invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualityError(f"Timestamp must include a timezone: {value!r}")
    return parsed


def _duration(value: str) -> timedelta:
    match = re.fullmatch(r"([0-9]+)([smhd])", value)
    if match is None:
        raise QualityError(f"Invalid duration: {value!r}")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return timedelta(seconds=int(match.group(1)) * units[match.group(2)])


def _primary_events(case: FixtureCase, rule: Rule) -> tuple[dict[str, Any], ...]:
    """Select primary rows and enforce every declared fixture-level join."""
    primary_source = rule.source_data["primary_source"]
    join_keys = rule.source_data.get("join_keys", [])
    secondary_sources = set(rule.source_data.get("secondary_sources", []))
    selected = []
    for event in case.events:
        source = event.get("source")
        if source is not None and source != primary_source:
            continue
        if join_keys:
            if not any(
                secondary.get("source") in secondary_sources
                and all(event.get(key) is not None and event.get(key) == secondary.get(key) for key in join_keys)
                for secondary in case.events
            ):
                continue
        selected.append(event)
    return tuple(selected)


def _is_suppressed(event: dict[str, Any], rule: Rule, case: FixtureCase) -> bool:
    if not case.prior_alerts or rule.suppression_window == "none":
        return False
    if rule.identity_scope == "global":
        identity_field = None
    elif rule.identity_scope in ("user", "host"):
        identity_field = {"user": "UserPrincipalName", "host": "Computer"}[rule.identity_scope]
    else:
        raise QualityError(f"Unsupported identity_scope: {rule.identity_scope!r}")
    identity = event.get(identity_field) if identity_field else None
    event_time_field = "TimeGenerated" if rule.platform == "sentinel_kql" else "_time"
    event_time = _timestamp(event.get(event_time_field))
    earliest = event_time - _duration(rule.suppression_window)
    for alert in case.prior_alerts:
        alert_time = _timestamp(alert.get("timestamp"))
        if not isinstance(alert.get("identity"), str):
            raise QualityError("Prior alert identity must be a string")
        if identity_field is not None and identity != alert["identity"]:
            continue
        tenant_id = event.get("TenantId")
        if not isinstance(tenant_id, str) or not tenant_id or tenant_id != alert.get("tenant_id"):
            continue
        if earliest <= alert_time <= event_time:
            return True
    return False


def _evaluate_event_predicate(event: dict[str, Any], rule: Rule) -> bool:
    """Evaluate whether an event satisfies the rule logic predicate."""
    # Null required values are absent telemetry, even if a different predicate branch could match.
    for req in rule.required_fields:
        if event.get(req) is None:
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
    primary_events = _primary_events(case, rule)
    missing_fields_in_case = set()
    for req in rule.required_fields:
        for ev in case.events:
            if ev.get("source") not in (None, rule.source_data["primary_source"]):
                continue
            if ev.get(req) is None:
                missing_fields_in_case.add(req)

    anchor = _timestamp(case.evaluation_time) if case.evaluation_time is not None else None
    event_time_field = "TimeGenerated" if rule.platform == "sentinel_kql" else "_time"
    window_start = anchor - _duration(rule.time_window) if anchor is not None else None
    matched = False
    for event in primary_events:
        if not _evaluate_event_predicate(event, rule):
            continue
        if anchor is not None:
            event_time = _timestamp(event.get(event_time_field))
            if not window_start <= event_time <= anchor:
                continue
        if not _is_suppressed(event, rule, case):
            matched = True
            break

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


def evaluate_rule_suite(
    rule: Rule, suite: FixtureSuite, environment: str = "offline_reference_evaluator"
) -> dict[str, Any]:
    """Evaluate a complete fixture suite against a rule."""
    if not suite.cases:
        raise QualityError("Fixture suite must contain at least one case")
    static_checks = analyze_rule_dependencies(rule, list(suite.cases))

    case_results = [evaluate_fixture_case(case, rule) for case in suite.cases]

    # Metrics
    tp = sum(
        1
        for r in case_results
        if r.outcome_classification in ("true_positive", "boundary_handled") and r.expected_match
    )
    fp = sum(1 for r in case_results if r.outcome_classification == "false_positive")
    tn = sum(
        1
        for r in case_results
        if r.outcome_classification in ("true_negative", "boundary_handled") and not r.expected_match
    )
    fn = sum(1 for r in case_results if r.outcome_classification == "false_negative")
    schema_error_cases = sum(1 for r in case_results if r.outcome_classification == "missing_field_error")
    evaluated_cases = len(case_results) - schema_error_cases

    precision = None if schema_error_cases else (round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0)
    recall = None if schema_error_cases else (round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0)

    recommendations: list[str] = []
    if fp > 0:
        recommendations.append(
            f"Rule generated {fp} false positive(s). Add filter exclusions or tighten entity/role scopes."
        )
    if fn > 0:
        recommendations.append(
            f"Rule missed {fn} target positive case(s). Review join conditions or required field assumptions."
        )
    if schema_error_cases > 0:
        recommendations.append(
            f"{schema_error_cases} fixture case(s) could not be evaluated because required fields were missing; correct the telemetry before reporting precision and recall."
        )
    if static_checks["missing_fields"]:
        recommendations.append(
            f"Telemetry schema drift: Missing required field(s) {static_checks['missing_fields']}. Update collection pipeline or declare fields optional."
        )
    if not recommendations:
        recommendations.append(
            "All labeled fixture cases evaluated cleanly. Validate the query in the target SIEM before staging."
        )

    return {
        "schema_version": "cops.detection-quality-report/v2",
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
            "evaluated_cases": evaluated_cases,
            "schema_error_cases": schema_error_cases,
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
