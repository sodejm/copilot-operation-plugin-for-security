"""Purple-team handoff and evidence correlation contracts."""

from __future__ import annotations

import re
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from cops.evidence.canonical import canonical, digest, timestamp

from .contracts import WorkflowContractError

PURPLE_SCHEMA_VERSION = "cops.purple-team-handoff/v1"
SIGMA_SUBSET_VERSION = "cops.sigma-selection-equality/v1"
KQL_SUBSET_VERSION = "cops.kql-conjunctive-string-equality/v1"

_FIELD_PATH = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
_FIELD_PATH_RE = re.compile(rf"^{_FIELD_PATH}$")
_KQL_CLAUSE_RE = re.compile(rf'(?P<field>{_FIELD_PATH}) == "(?P<value>(?:[^"\\\x00-\x1f]|\\["\\])*)"')
_MAX_RULE_CONDITIONS = 64
_MAX_KQL_BYTES = 65_536


@dataclass(frozen=True)
class PurpleTeamHandoffContract:
    """Validated handoff from any offensive result to detection replay."""

    _document: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_document", _copy_and_validate_handoff(self._document))

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> PurpleTeamHandoffContract:
        return cls(document)

    def to_dict(self) -> dict[str, Any]:
        return _copy_and_validate_handoff(self._document)

    @property
    def handoff_digest(self) -> str:
        return digest(_copy_and_validate_handoff(self._document))


def emit_purple_team_handoff(
    source_result: dict[str, Any],
    expected_telemetry: list[dict[str, str]],
    correlation_ids: list[str],
    window: dict[str, str],
    evidence_refs: list[str],
) -> PurpleTeamHandoffContract:
    """Create a handoff for a finding or simulation without widening execution scope."""
    return PurpleTeamHandoffContract.from_dict(
        {
            "schema_version": PURPLE_SCHEMA_VERSION,
            "source": deepcopy(source_result),
            "expected_telemetry": deepcopy(expected_telemetry),
            "correlation_ids": list(correlation_ids),
            "time_window": dict(window),
            "evidence_refs": list(evidence_refs),
            "detection_result": {
                "status": "indeterminate",
                "reason": "not_evaluated",
                "matched_telemetry": 0,
                "matched_alerts": 0,
            },
        }
    )


def evaluate_purple_team_handoff(
    handoff: PurpleTeamHandoffContract,
    telemetry: list[dict[str, Any]] | None,
    alerts: list[dict[str, Any]] | None,
    attack_fixture: Iterable[dict[str, Any]] = (),
    benign_fixture: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Correlate evidence and execute the generated Sigma and KQL proposals."""
    document = handoff.to_dict()
    _validate_handoff(document)
    rule = {"all": deepcopy(document["expected_telemetry"]), "correlation_ids": document["correlation_ids"]}
    proposal = {
        "sigma": _sigma_proposal(document["expected_telemetry"]),
        "kql": _kql_proposal(document["expected_telemetry"]),
    }
    attack_events = list(attack_fixture)
    benign_events = list(benign_fixture)
    sigma_counts = {
        "attack_matches": execute_sigma_proposal(proposal["sigma"], attack_events),
        "benign_matches": execute_sigma_proposal(proposal["sigma"], benign_events),
    }
    kql_counts = {
        "attack_matches": execute_kql_proposal(proposal["kql"], attack_events),
        "benign_matches": execute_kql_proposal(proposal["kql"], benign_events),
    }
    if sigma_counts != kql_counts:
        raise WorkflowContractError("rule_execution_mismatch")
    rule_execution = {
        "sigma": {
            "status": "executed",
            "supported_subset": SIGMA_SUBSET_VERSION,
            "proposal_digest": digest(proposal["sigma"]),
            **sigma_counts,
        },
        "kql": {
            "status": "executed",
            "supported_subset": KQL_SUBSET_VERSION,
            "proposal_digest": digest(proposal["kql"]),
            **kql_counts,
        },
        "counts_agree": True,
    }
    base = {
        "rule": rule,
        "rule_proposal": proposal,
        "fixture_counts": sigma_counts,
        "rule_execution": rule_execution,
    }
    if not document["evidence_refs"]:
        return {**base, **_evaluation("indeterminate", "missing_evidence", [], [])}
    if telemetry is None:
        return {**base, **_evaluation("instrumentation_gap", "logs_unavailable", [], [])}
    matching_telemetry = [
        event for event in _matching_events(rule, telemetry) if _in_window(event, document["time_window"])
    ]
    if not matching_telemetry:
        return {
            **base,
            **_evaluation("instrumentation_gap", "expected_telemetry_not_captured", [], []),
        }
    if alerts is None:
        return {
            **base,
            **_evaluation("indeterminate", "alert_evidence_unavailable", matching_telemetry, []),
        }
    matching_alerts = [
        event
        for event in _matching_events(rule, alerts)
        if event.get("alert") is True and _in_window(event, document["time_window"])
    ]
    if not matching_alerts:
        return {
            **base,
            **_evaluation("detection_gap", "expected_alert_not_observed", matching_telemetry, []),
        }
    return {
        **base,
        **_evaluation("verified_detection", "telemetry_and_alert_correlated", matching_telemetry, matching_alerts),
    }


def execute_simple_rule(rule: dict[str, Any], events: Iterable[dict[str, Any]]) -> int:
    """Execute the generated equality rule against fixture events."""
    if not isinstance(rule, dict) or set(rule) != {"all", "correlation_ids"}:
        raise WorkflowContractError("simple_rule")
    conditions = rule["all"]
    correlations = rule["correlation_ids"]
    if not isinstance(conditions, list) or not isinstance(correlations, list):
        raise WorkflowContractError("simple_rule")
    return len(_matching_events(rule, list(events)))


def execute_sigma_proposal(proposal: dict[str, Any], events: Iterable[dict[str, Any]]) -> int:
    """Execute the supported Sigma selection-equality subset against events."""
    if not isinstance(proposal, dict) or set(proposal) != {"title", "detection"}:
        raise WorkflowContractError("sigma_rule_unsupported")
    if not isinstance(proposal["title"], str) or not proposal["title"]:
        raise WorkflowContractError("sigma_rule_unsupported")
    detection = proposal["detection"]
    if (
        not isinstance(detection, dict)
        or set(detection) != {"selection", "condition"}
        or detection["condition"] != "selection"
    ):
        raise WorkflowContractError("sigma_rule_unsupported")
    selection = _validated_selection(detection["selection"], "sigma_rule_unsupported")
    return _count_selection_matches(selection, events)


def execute_kql_proposal(proposal: str, events: Iterable[dict[str, Any]]) -> int:
    """Execute the supported conjunctive KQL string-equality subset against events."""
    selection = _parse_kql_selection(proposal)
    return _count_selection_matches(selection, events)


def _matching_events(rule: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if isinstance(event, dict)
        and all(_lookup(event, condition["field"]) == condition["value"] for condition in rule["all"])
        and _has_correlation(event, rule["correlation_ids"])
    ]


def _lookup(event: dict[str, Any], path: str) -> Any:
    current: Any = event
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _validated_selection(selection: Any, error_code: str) -> dict[str, str]:
    if (
        not isinstance(selection, dict)
        or not selection
        or len(selection) > _MAX_RULE_CONDITIONS
        or not all(
            isinstance(field, str) and _FIELD_PATH_RE.fullmatch(field) is not None and isinstance(value, str)
            for field, value in selection.items()
        )
    ):
        raise WorkflowContractError(error_code)
    return dict(selection)


def _count_selection_matches(selection: dict[str, str], events: Iterable[dict[str, Any]]) -> int:
    return sum(
        1
        for event in events
        if isinstance(event, dict) and all(_lookup(event, field) == value for field, value in selection.items())
    )


def _parse_kql_selection(proposal: Any) -> dict[str, str]:
    if not isinstance(proposal, str) or not proposal or len(proposal.encode("utf-8")) > _MAX_KQL_BYTES:
        raise WorkflowContractError("kql_rule_unsupported")
    selection: dict[str, str] = {}
    position = 0
    while position < len(proposal):
        match = _KQL_CLAUSE_RE.match(proposal, position)
        if match is None:
            raise WorkflowContractError("kql_rule_unsupported")
        field = match.group("field")
        if field in selection or len(selection) >= _MAX_RULE_CONDITIONS:
            raise WorkflowContractError("kql_rule_unsupported")
        selection[field] = _unescape_kql(match.group("value"))
        position = match.end()
        if position == len(proposal):
            break
        if not proposal.startswith(" and ", position):
            raise WorkflowContractError("kql_rule_unsupported")
        position += len(" and ")
        if position == len(proposal):
            raise WorkflowContractError("kql_rule_unsupported")
    return _validated_selection(selection, "kql_rule_unsupported")


def _unescape_kql(value: str) -> str:
    decoded: list[str] = []
    position = 0
    while position < len(value):
        if value[position] != "\\":
            decoded.append(value[position])
            position += 1
            continue
        if position + 1 >= len(value) or value[position + 1] not in {'"', "\\"}:
            raise WorkflowContractError("kql_rule_unsupported")
        decoded.append(value[position + 1])
        position += 2
    return "".join(decoded)


def _has_correlation(event: dict[str, Any], expected: list[str]) -> bool:
    if not expected:
        return False
    values: list[str] = []
    direct = event.get("correlation_id")
    if isinstance(direct, str):
        values.append(direct)
    many = event.get("correlation_ids")
    if isinstance(many, list):
        values.extend(value for value in many if isinstance(value, str))
    return bool(set(values) & set(expected))


def _in_window(event: dict[str, Any], window: dict[str, str]) -> bool:
    observed = event.get("timestamp")
    if not isinstance(observed, str):
        return False
    try:
        return timestamp(window["start"]) <= timestamp(observed) <= timestamp(window["end"])
    except (TypeError, ValueError):
        return False


def _evaluation(
    status: str,
    reason: str,
    matching_telemetry: list[dict[str, Any]],
    matching_alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "matched_telemetry": len(matching_telemetry),
        "matched_alerts": len(matching_alerts),
    }


def _copy_and_validate_handoff(document: Any) -> dict[str, Any]:
    try:
        copied = deepcopy(document)
        canonical(copied, max_bytes=2_097_152)
        _validate_handoff(copied)
    except WorkflowContractError:
        raise
    except Exception as exc:
        raise WorkflowContractError("purple_handoff") from exc
    return copied


def _validate_handoff(doc: Any) -> None:
    required = {
        "schema_version",
        "source",
        "expected_telemetry",
        "correlation_ids",
        "time_window",
        "evidence_refs",
        "detection_result",
    }
    if not isinstance(doc, dict) or set(doc) != required or doc["schema_version"] != PURPLE_SCHEMA_VERSION:
        raise WorkflowContractError("purple_shape")
    source = doc["source"]
    if (
        not isinstance(source, dict)
        or set(source) != {"kind", "ref"}
        or source["kind"] not in {"finding", "simulation"}
        or not isinstance(source["ref"], str)
        or not source["ref"]
    ):
        raise WorkflowContractError("purple_source")
    _validate_expected_telemetry(doc["expected_telemetry"])
    correlations = doc["correlation_ids"]
    if not isinstance(correlations, list) or not correlations or len(set(correlations)) != len(correlations):
        raise WorkflowContractError("correlation_ids")
    if not all(isinstance(item, str) and item for item in correlations):
        raise WorkflowContractError("correlation_ids")
    window = doc["time_window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise WorkflowContractError("time_window")
    if timestamp(window["start"]) >= timestamp(window["end"]):
        raise WorkflowContractError("time_window")
    evidence = doc["evidence_refs"]
    if not isinstance(evidence, list) or not all(isinstance(item, str) and item for item in evidence):
        raise WorkflowContractError("evidence_refs")
    result = doc["detection_result"]
    if (
        not isinstance(result, dict)
        or set(result) != {"status", "reason", "matched_telemetry", "matched_alerts"}
        or result["status"] not in {"instrumentation_gap", "detection_gap", "verified_detection", "indeterminate"}
        or not isinstance(result["reason"], str)
        or type(result["matched_telemetry"]) is not int
        or result["matched_telemetry"] < 0
        or type(result["matched_alerts"]) is not int
        or result["matched_alerts"] < 0
    ):
        raise WorkflowContractError("detection_result")


def _validate_expected_telemetry(expected: Any) -> None:
    if not isinstance(expected, list) or not expected:
        raise WorkflowContractError("expected_telemetry")
    fields: set[str] = set()
    for item in expected:
        if (
            not isinstance(item, dict)
            or set(item) != {"field", "value"}
            or not isinstance(item["field"], str)
            or _FIELD_PATH_RE.fullmatch(item["field"]) is None
            or not isinstance(item["value"], str)
        ):
            raise WorkflowContractError("expected_telemetry")
        if item["field"] in fields:
            raise WorkflowContractError("duplicate_expected_telemetry_field")
        fields.add(item["field"])


def _sigma_proposal(expected: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "title": "COPS purple-team correlation proposal",
        "detection": {"selection": _selection(expected), "condition": "selection"},
    }


def _kql_proposal(expected: list[dict[str, str]]) -> str:
    _validate_expected_telemetry(expected)
    return " and ".join(f'{item["field"]} == "{_escape_kql(item["value"])}"' for item in expected)


def _selection(expected: list[dict[str, str]]) -> dict[str, str]:
    _validate_expected_telemetry(expected)
    return {item["field"]: item["value"] for item in expected}


def _escape_kql(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
