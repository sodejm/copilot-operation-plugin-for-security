"""Immutable typed data models for Detection Quality Workbench."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class QualityError(ValueError):
    """Raised when detection rule validation or fixture evaluation fails."""


@dataclass(frozen=True)
class Rule:
    """A detection rule contract specification."""

    rule_id: str
    name: str
    version: str
    platform: str  # "sentinel_kql" | "splunk_spl"
    severity: str
    source_data: dict[str, Any]
    required_fields: tuple[str, ...]
    time_window: str
    logic: dict[str, Any]
    owner: str
    description: str = ""
    optional_fields: tuple[str, ...] = field(default_factory=tuple)
    suppression_window: str = "none"
    identity_scope: str = "global"
    expected_signal: str = ""
    mitre_attack: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        required = [
            "rule_id", "name", "version", "platform", "severity",
            "source_data", "required_fields", "time_window", "logic", "owner"
        ]
        for f in required:
            if f not in data:
                raise QualityError(f"Missing required rule field: {f}")
        return cls(
            rule_id=data["rule_id"],
            name=data["name"],
            version=data["version"],
            platform=data["platform"],
            severity=data["severity"],
            source_data=dict(data["source_data"]),
            required_fields=tuple(data["required_fields"]),
            time_window=data["time_window"],
            logic=dict(data["logic"]),
            owner=data["owner"],
            description=data.get("description", ""),
            optional_fields=tuple(data.get("optional_fields", [])),
            suppression_window=data.get("suppression_window", "none"),
            identity_scope=data.get("identity_scope", "global"),
            expected_signal=data.get("expected_signal", ""),
            mitre_attack=tuple(data.get("mitre_attack", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cops.detection-rule/v1",
            "rule_id": self.rule_id,
            "name": self.name,
            "version": self.version,
            "platform": self.platform,
            "severity": self.severity,
            "description": self.description,
            "source_data": self.source_data,
            "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "time_window": self.time_window,
            "suppression_window": self.suppression_window,
            "identity_scope": self.identity_scope,
            "expected_signal": self.expected_signal,
            "mitre_attack": list(self.mitre_attack),
            "logic": self.logic,
            "owner": self.owner,
        }


@dataclass(frozen=True)
class FixtureCase:
    """A single labeled test case containing telemetry events."""

    case_id: str
    label: str  # "positive" | "negative" | "boundary"
    expected_match: bool
    events: tuple[dict[str, Any], ...]
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FixtureCase:
        required = ["case_id", "label", "expected_match", "events"]
        for f in required:
            if f not in data:
                raise QualityError(f"Missing required fixture case field: {f}")
        return cls(
            case_id=data["case_id"],
            label=data["label"],
            expected_match=bool(data["expected_match"]),
            events=tuple(dict(e) for e in data["events"]),
            description=data.get("description", ""),
            tags=tuple(data.get("tags", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "description": self.description,
            "label": self.label,
            "expected_match": self.expected_match,
            "tags": list(self.tags),
            "events": [dict(e) for e in self.events],
        }


@dataclass(frozen=True)
class FixtureSuite:
    """A suite of fixture cases for testing a specific rule."""

    fixture_suite_id: str
    target_rule_id: str
    cases: tuple[FixtureCase, ...]
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FixtureSuite:
        required = ["fixture_suite_id", "target_rule_id", "cases"]
        for f in required:
            if f not in data:
                raise QualityError(f"Missing required fixture suite field: {f}")
        return cls(
            fixture_suite_id=data["fixture_suite_id"],
            target_rule_id=data["target_rule_id"],
            cases=tuple(FixtureCase.from_dict(c) for c in data["cases"]),
            description=data.get("description", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cops.detection-fixtures/v1",
            "fixture_suite_id": self.fixture_suite_id,
            "target_rule_id": self.target_rule_id,
            "description": self.description,
            "cases": [c.to_dict() for c in self.cases],
        }


@dataclass(frozen=True)
class CaseResult:
    """Outcome of evaluating one fixture case."""

    case_id: str
    label: str
    expected_match: bool
    actual_match: bool
    outcome_classification: str
    details: str
    missing_fields: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "label": self.label,
            "expected_match": self.expected_match,
            "actual_match": self.actual_match,
            "outcome_classification": self.outcome_classification,
            "details": self.details,
        }
