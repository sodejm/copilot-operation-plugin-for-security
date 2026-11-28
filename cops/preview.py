"""Pure execution preview for routed COPS specialist work."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .contracts import ActionPlan
from .routing.models import RoutingDecision

UNKNOWN = "unknown"


@dataclass(frozen=True)
class PreviewBudget:
    model: str = UNKNOWN
    token_limit: int | str = UNKNOWN
    time_limit_seconds: int | str = UNKNOWN
    cost_limit: float | str = UNKNOWN

    def to_dict(self) -> dict[str, object]:
        return {
            "model": self.model,
            "token_limit": self.token_limit,
            "time_limit_seconds": self.time_limit_seconds,
            "cost_limit": self.cost_limit,
        }


@dataclass(frozen=True)
class PreviewAction:
    specialist_id: str
    action: str
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    authorization: str = UNKNOWN
    expected_evidence: tuple[str, ...] = ()
    noise: str = UNKNOWN

    def to_dict(self) -> dict[str, object]:
        return {
            "specialist_id": self.specialist_id,
            "action": self.action,
            "effects": {"reads": list(self.reads), "writes": list(self.writes)},
            "destinations": list(self.destinations) if self.destinations else [UNKNOWN],
            "authorization": self.authorization,
            "expected_evidence": list(self.expected_evidence) if self.expected_evidence else [UNKNOWN],
            "noise": self.noise,
        }


@dataclass(frozen=True)
class ExecutionPreview:
    version: str
    status: Literal["preview", "clarification_required"]
    specialists: tuple[str, ...]
    actions: tuple[PreviewAction, ...]
    budget: PreviewBudget
    side_effects_performed: bool = False
    approvals_consumed: bool = False
    connectors_invoked: bool = False
    workers_started: bool = False
    state_written: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "status": self.status,
            "specialists": list(self.specialists),
            "actions": [action.to_dict() for action in self.actions],
            "budget": self.budget.to_dict(),
            "side_effects_performed": self.side_effects_performed,
            "approvals_consumed": self.approvals_consumed,
            "connectors_invoked": self.connectors_invoked,
            "workers_started": self.workers_started,
            "state_written": self.state_written,
        }


def build_execution_preview(
    decision: RoutingDecision,
    *,
    actions: Mapping[str, Sequence[PreviewAction]] | None = None,
    budget: PreviewBudget | None = None,
) -> ExecutionPreview:
    """Describe intended execution without I/O, authorization, or state mutation."""
    selected: list[str] = []
    if decision.primary_profile is not None:
        selected.append(decision.primary_profile.id)
    if decision.triad_plan is not None:
        selected.extend((decision.triad_plan.skeptic.specialist_id, decision.triad_plan.auditor.specialist_id))
    selected = list(dict.fromkeys(selected))

    plan: list[PreviewAction] = []
    for specialist_id in selected:
        configured = tuple((actions or {}).get(specialist_id, ()))
        if configured:
            if any(action.specialist_id != specialist_id for action in configured):
                raise ValueError("preview action specialist does not match its mapping key")
            plan.extend(configured)
        else:
            profile = next(
                (
                    candidate.profile
                    for candidate in decision.ranked_candidates
                    if candidate.profile.id == specialist_id
                ),
                decision.primary_profile
                if decision.primary_profile and decision.primary_profile.id == specialist_id
                else None,
            )
            authorization = (
                "interactive authorization required"
                if profile is not None and profile.interactive_authorization_required
                else "no interactive authorization declared"
            )
            plan.append(
                PreviewAction(
                    specialist_id=specialist_id,
                    action=UNKNOWN,
                    authorization=authorization,
                )
            )

    return ExecutionPreview(
        version="cops.execution-preview/v1",
        status="preview" if decision.status == "routed" else "clarification_required",
        specialists=tuple(selected),
        actions=tuple(plan),
        budget=budget or PreviewBudget(),
    )


def preview_action_plan(plan: ActionPlan) -> dict[str, object]:
    """Expose validated action metadata without credentials or execution I/O."""
    document = plan.to_dict()
    actions = []
    for operation in document["operations"]:
        actions.append(
            {
                "step_id": operation["step_id"],
                "tool": operation["tool"],
                "tool_version": operation["tool_version"],
                "action": operation["action"],
                "timeout_seconds": operation["timeout_seconds"],
                "effects": operation.get("side_effects", UNKNOWN),
                "destinations": operation.get("egress_policy", UNKNOWN),
                "expected_evidence": operation.get("expected_evidence", UNKNOWN),
                "cleanup": operation.get("cleanup", UNKNOWN),
                "noise": UNKNOWN,
            }
        )
    return {
        "version": "cops.action-plan-preview/v1",
        "status": "preview",
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "specialists": [plan.specialist_id],
        "target": document["target"],
        "actions": actions,
        "budget": document["limits"],
        "authorization": "fresh authorization bound to this plan digest, target, actions, and worker",
        "side_effects_performed": False,
        "approvals_consumed": False,
        "connectors_invoked": False,
        "workers_started": False,
        "state_written": False,
    }


def render_preview(document: Mapping[str, object]) -> str:
    """Render previews without claiming estimates or concrete actions we lack."""
    lines = [
        f"Status: {document['status']}",
        "Specialists: " + ", ".join(document.get("specialists", [])),
    ]
    if "target" in document:
        lines.append("Target: " + json.dumps(document["target"], sort_keys=True))
    for index, action in enumerate(document.get("actions", []), 1):
        lines.append(f"{index}. {action.get('action', UNKNOWN)}")
        for key in ("target", "dependencies", "effects", "destinations", "expected_evidence", "cleanup", "noise"):
            lines.append(f"   {key}: " + json.dumps(action.get(key, UNKNOWN), sort_keys=True))
        lines.append("   authorization: " + str(action.get("authorization", document.get("authorization", UNKNOWN))))
    lines.append("Budget: " + json.dumps(document.get("budget", UNKNOWN), sort_keys=True))
    lines.append("No execution state or authorization was changed.")
    return "\n".join(lines)
