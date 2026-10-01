"""Static dependency and schema analysis for detection rules."""

from __future__ import annotations

from typing import Any

from .models import FixtureCase, Rule


def analyze_rule_dependencies(rule: Rule, cases: list[FixtureCase]) -> dict[str, Any]:
    """Inspect rule declarations against fixture events for missing fields and schema drift."""
    missing_fields_set: set[str] = set()
    schema_drift_detected = False

    required = set(rule.required_fields)

    for case in cases:
        for event in case.events:
            present_keys = set(event.keys())
            missing_in_event = required - present_keys
            if missing_in_event:
                missing_fields_set.update(missing_in_event)
                schema_drift_detected = True

    return {
        "required_fields_present": len(missing_fields_set) == 0,
        "missing_fields": sorted(missing_fields_set),
        "schema_drift_detected": schema_drift_detected,
    }
