"""Data models for specialist agent profiles and dynamic routing decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SpecialistProfile:
    """Canonical metadata for a specialist cybersecurity agent profile."""

    id: str
    display_name: str
    domain: str
    criticality: str
    interactive_authorization_required: bool
    description: str
    primary_plugin: str
    skills: tuple[str, ...]
    tools: tuple[str, ...]
    contract_file: str
    intent_keywords: tuple[str, ...]
    triad_defaults: dict[str, str] | None = None

    @property
    def is_critical(self) -> bool:
        return self.criticality == "critical"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "display_name": self.display_name,
            "domain": self.domain,
            "criticality": self.criticality,
            "interactive_authorization_required": self.interactive_authorization_required,
            "description": self.description,
            "primary_plugin": self.primary_plugin,
            "skills": list(self.skills),
            "tools": list(self.tools),
            "contract_file": self.contract_file,
            "intent_keywords": list(self.intent_keywords),
        }
        if self.triad_defaults is not None:
            data["triad_defaults"] = dict(self.triad_defaults)
        return data


@dataclass(frozen=True)
class TriadMember:
    """One participant in a three-agent Triad orchestration topology."""

    role: str  # "primary", "skeptic", "auditor"
    specialist_id: str
    display_name: str
    review_focus: str
    deliverable: str

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "specialist_id": self.specialist_id,
            "display_name": self.display_name,
            "review_focus": self.review_focus,
            "deliverable": self.deliverable,
        }


@dataclass(frozen=True)
class TriadExecutionPlan:
    """Orchestration topology for critical security tasks."""

    task_description: str
    criticality: str
    primary: TriadMember
    skeptic: TriadMember
    auditor: TriadMember
    handoff_steps: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_description": self.task_description,
            "criticality": self.criticality,
            "primary": self.primary.to_dict(),
            "skeptic": self.skeptic.to_dict(),
            "auditor": self.auditor.to_dict(),
            "handoff_steps": list(self.handoff_steps),
        }


@dataclass(frozen=True)
class RoutingDecision:
    """The result of routing an operator request to specialist agent profiles."""

    query: str
    primary_profile: SpecialistProfile
    confidence: float
    match_reasons: tuple[str, ...]
    criticality: str
    interactive_authorization_required: bool
    recommended_skills: tuple[str, ...]
    triad_plan: TriadExecutionPlan | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "primary_profile": self.primary_profile.to_dict(),
            "confidence": round(self.confidence, 3),
            "match_reasons": list(self.match_reasons),
            "criticality": self.criticality,
            "interactive_authorization_required": self.interactive_authorization_required,
            "recommended_skills": list(self.recommended_skills),
            "triad_plan": self.triad_plan.to_dict() if self.triad_plan is not None else None,
        }
