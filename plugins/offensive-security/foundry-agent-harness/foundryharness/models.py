"""Immutable typed data models for Foundry adversarial agent testing."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._schema_validation import SchemaValidationError, validate
from .redaction import redact_text


class HarnessError(ValueError):
    """Raised when scenario parsing, gate evaluation, or harness execution fails."""


@dataclass(frozen=True)
class Scenario:
    """Readable v1 inventory used by the offline simulator, never execution authority."""

    scenario_id: str
    title: str
    target_agent: dict[str, str]
    approved_test_environment: str
    attacker_controlled_surface: str
    objective: str
    injected_artifact: str
    legitimate_task: str
    principal_tenant: dict[str, str]
    tool_permissions: tuple[str, ...]
    expected_safe_behavior: str
    stop_conditions: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scenario:
        if data.get("schema_version", "foundry.scenario/v1") != "foundry.scenario/v1":
            raise HarnessError("Legacy scenario reader requires foundry.scenario/v1")
        required = [
            "scenario_id",
            "title",
            "target_agent",
            "approved_test_environment",
            "attacker_controlled_surface",
            "objective",
            "injected_artifact",
            "legitimate_task",
            "principal_tenant",
            "tool_permissions",
            "expected_safe_behavior",
            "stop_conditions",
        ]
        for field in required:
            if field not in data:
                raise HarnessError(f"Missing required scenario field: {field}")
        return cls(
            scenario_id=data["scenario_id"],
            title=data["title"],
            target_agent=dict(data["target_agent"]),
            approved_test_environment=data["approved_test_environment"],
            attacker_controlled_surface=data["attacker_controlled_surface"],
            objective=data["objective"],
            injected_artifact=data["injected_artifact"],
            legitimate_task=data["legitimate_task"],
            principal_tenant=dict(data["principal_tenant"]),
            tool_permissions=tuple(data["tool_permissions"]),
            expected_safe_behavior=data["expected_safe_behavior"],
            stop_conditions=tuple(data["stop_conditions"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "foundry.scenario/v1",
            "scenario_id": self.scenario_id,
            "title": self.title,
            "target_agent": self.target_agent,
            "approved_test_environment": self.approved_test_environment,
            "attacker_controlled_surface": self.attacker_controlled_surface,
            "objective": self.objective,
            "injected_artifact": self.injected_artifact,
            "legitimate_task": self.legitimate_task,
            "principal_tenant": self.principal_tenant,
            "tool_permissions": list(self.tool_permissions),
            "expected_safe_behavior": self.expected_safe_behavior,
            "stop_conditions": list(self.stop_conditions),
        }


@dataclass(frozen=True)
class SideEffectRecord:
    """A reversible recorded side-effect from authorized mock tool execution."""

    effect_id: str
    action: str
    target: str
    parameters: dict[str, Any]
    reversible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "action": self.action,
            "target": self.target,
            "parameters": self.parameters,
            "reversible": self.reversible,
        }


@dataclass(frozen=True)
class GateDecision:
    """An independent authorization decision for a proposed tool execution."""

    allowed: bool
    reason: str
    decision_type: str = "deny"  # "allow" | "deny"
    effect_descriptor: str | None = None


@dataclass(frozen=True)
class ExecutionEvent:
    """The complete outcome trace for a scenario execution."""

    trace_id: str
    scenario_id: str
    title: str
    surface: str
    outcome_level: str  # "model_output_only" | "attempted_tool_call" | "denied_tool_call" | "executed_mock_effect"
    authorization_decision: str  # "allow" | "deny" | "not_applicable"
    model_response_summary: str
    risk_assessment: str
    evidence_citations: tuple[str, ...]
    attempted_tool: dict[str, Any] | None = None
    gate_denial_reason: str | None = None
    executed_side_effect: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "scenario_id": self.scenario_id,
            "title": self.title,
            "surface": self.surface,
            "trace_id": self.trace_id,
            "outcome_level": self.outcome_level,
            "authorization_decision": self.authorization_decision,
            "model_response_summary": self.model_response_summary,
            "risk_assessment": self.risk_assessment,
            "evidence_citations": list(self.evidence_citations),
        }
        if self.attempted_tool:
            result["attempted_tool"] = self.attempted_tool
        if self.gate_denial_reason:
            result["gate_denial_reason"] = self.gate_denial_reason
        if self.executed_side_effect:
            result["executed_side_effect"] = self.executed_side_effect
        return result


def contract_digest(value: Any) -> str:
    """Digest a detached, finite JSON contract using stable UTF-8 encoding."""
    return hashlib.sha256(_contract_json(value).encode("utf-8")).hexdigest()


def _contract_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise HarnessError("Contract must contain finite JSON data") from exc


def _contract_schema(name: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parent.parent / "schemas" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_contract(value: Any, schema: dict[str, Any]) -> None:
    try:
        validate(value, schema)
    except (SchemaValidationError, RecursionError) as exc:
        raise HarnessError("Contract does not match its strict versioned schema") from exc


def _immutable_record(record_type: Any, encoded: str) -> Any:
    record = object.__new__(record_type)
    object.__setattr__(record, "_json", encoded)
    return record


_FORBIDDEN_EXECUTION_KEY = re.compile(
    r"(?i)(?:auth|credential|password|passwd|secret|token|api[_-]?key|cookie|"
    r"command|shell|executable|binary|transport|endpoint|url|host|port|path)"
)
_CREDENTIAL_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+\S+|\bsk-[A-Za-z0-9_-]{8,}\b")


def _check_request_data(value: Any) -> None:
    """Arguments are inert bounded data; profiles alone select the executable."""
    if isinstance(value, dict):
        for key, item in value.items():
            if _FORBIDDEN_EXECUTION_KEY.search(key):
                raise HarnessError("Executable request contains a forbidden argument field")
            _check_request_data(item)
    elif isinstance(value, str) and (
        _CREDENTIAL_VALUE.search(value) or redact_text(value) != value or re.search(r"(?i)(?:https?|wss?|tcp|udp)://", value)
    ):
        raise HarnessError("Executable request contains credentials or a network destination")


def _reject_credential_values(value: Any) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _reject_credential_values(item)
    elif isinstance(value, list):
        for item in value:
            _reject_credential_values(item)
    elif isinstance(value, str) and (_CREDENTIAL_VALUE.search(value) or redact_text(value) != value):
        raise HarnessError("Executable scenarios cannot contain credential material")


@dataclass(frozen=True, init=False)
class ExecutableScenario:
    """A strict v2 contract; construction does not authorize or execute anything.

    Store canonical JSON rather than mutable nested dictionaries. All accessors
    return detached values, so callers cannot change an accepted binding.
    """

    _json: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutableScenario:
        encoded = _contract_json(data)
        if len(encoded.encode("utf-8")) > 65_536:
            raise HarnessError("Executable scenario exceeds its byte budget")
        value = json.loads(encoded)
        _validate_contract(value, _contract_schema("scenario-v2.schema.json"))
        _reject_credential_values(value)
        execution = value["execution"]
        if value["scenario_id"] != value["bindings"]["scenario_id"]:
            raise HarnessError("Scenario binding differs from scenario identity")
        if execution["profile_id"] != execution["request"]["profile_id"]:
            raise HarnessError("Request profile differs from execution profile")
        if contract_digest(execution["request"]) != value["bindings"]["envelope_digest"]:
            raise HarnessError("Request envelope digest differs from immutable binding")
        _check_request_data(execution["request"]["request"]["arguments"])
        expected = value["expected_outcome"]
        if expected["decision"] != "executed" and (
            expected["effect"]["expected_count"] != 0 or expected["canary"]["expected_observed"]
        ):
            raise HarnessError("Denied or unsupported scenarios cannot expect an observed effect")
        return _immutable_record(cls, encoded)

    @property
    def scenario_id(self) -> str:
        return self.to_dict()["scenario_id"]

    @property
    def execution(self) -> dict[str, Any]:
        return self.to_dict()["execution"]

    @property
    def bindings(self) -> dict[str, Any]:
        return self.to_dict()["bindings"]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._json)


@dataclass(frozen=True, init=False)
class TraceEvent:
    """A redacted observation with one evidence category and immutable bindings."""

    _json: str

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, redaction_values: tuple[str, ...] = ()) -> TraceEvent:
        value = json.loads(_contract_json(data))
        if isinstance(value, dict) and isinstance(value.get("summary"), str):
            summary = redact_text(value["summary"])
            for sensitive in redaction_values:
                if sensitive:
                    summary = summary.replace(sensitive, "[REDACTED]")
            value["summary"] = summary
        schema = _contract_schema("execution-trace.schema.json")
        _validate_contract(value, schema["$defs"]["event"])
        return _immutable_record(cls, _contract_json(value))

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._json)


@dataclass(frozen=True, init=False)
class ExecutionTrace:
    """A bounded trace distinguishes model text, attempts, denials, and effects.

    Digests bind evidence to an approved plan; an effect event additionally
    requires independent before/after observations. This validates evidence
    structure, without claiming the referenced observations were performed.
    """

    _json: str

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, redaction_values: tuple[str, ...] = ()) -> ExecutionTrace:
        value = json.loads(_contract_json(data))
        _validate_contract(value, _contract_schema("execution-trace.schema.json"))
        events = [TraceEvent.from_dict(event, redaction_values=redaction_values).to_dict() for event in value["events"]]
        value["events"] = events
        bindings_digest = contract_digest(value["bindings"])
        attempted = False
        terminal = False
        request_digest = None
        for index, event in enumerate(events):
            if event["sequence"] != index or event["bindings_digest"] != bindings_digest:
                raise HarnessError("Trace sequence or immutable binding differs")
            kind = event["event_kind"]
            if terminal:
                raise HarnessError("Trace contains events after a terminal decision")
            if kind == "model_output" and index != 0:
                raise HarnessError("Model output must precede tool activity")
            if kind == "tool_call_attempted":
                if attempted or index == 0:
                    raise HarnessError("Tool attempt requires preceding model output")
                attempted, request_digest = True, event["request_digest"]
            if kind in {"tool_call_denied", "tool_effect_executed"}:
                if not attempted or event["request_digest"] != request_digest:
                    raise HarnessError("Terminal tool evidence requires the same attempted request")
                terminal = True
            if kind == "unsupported_feature":
                terminal = True
        if value["cleanup"]["verified"] and value["cleanup"]["before_state_digest"] != value["cleanup"]["after_state_digest"]:
            raise HarnessError("Verified cleanup requires the original state digest")
        encoded = _contract_json(value)
        if len(events) > value["limits"]["max_trace_events"] or len(encoded.encode("utf-8")) > value["limits"]["max_trace_bytes"]:
            raise HarnessError("Execution trace exceeds its evidence budget")
        return _immutable_record(cls, encoded)

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._json)
