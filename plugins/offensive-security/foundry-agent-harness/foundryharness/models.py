"""Immutable typed data models for Foundry adversarial agent testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class HarnessError(ValueError):
    """Raised when scenario parsing, gate evaluation, or harness execution fails."""


@dataclass(frozen=True)
class Scenario:
    """An authorized adversarial evaluation scenario for a Microsoft Foundry agent."""

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
