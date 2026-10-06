"""COPS Specialist Agent Profiles and Dynamic Routing Engine."""

from .catalog import get_specialist, load_specialists_registry
from .classifier import route_request
from .handoff import (
    AuthorizationExpansionError,
    ConflictingEvidenceError,
    HandoffError,
    InvalidHandoffResultError,
    MaterialPlanModifiedError,
    MissingCapabilityError,
    accept_specialist_handoff,
    audit_and_approve_handoff,
    compute_material_plan_digest,
    execute_triad_handoff_workflow,
    propose_specialist_handoff,
    review_with_skeptic,
)
from .models import RoutingDecision, SpecialistProfile, TriadExecutionPlan, TriadMember
from .triad import assemble_triad_plan

__all__ = [
    "SpecialistProfile",
    "TriadMember",
    "TriadExecutionPlan",
    "RoutingDecision",
    "load_specialists_registry",
    "get_specialist",
    "route_request",
    "assemble_triad_plan",
    "HandoffError",
    "MissingCapabilityError",
    "ConflictingEvidenceError",
    "InvalidHandoffResultError",
    "AuthorizationExpansionError",
    "MaterialPlanModifiedError",
    "compute_material_plan_digest",
    "propose_specialist_handoff",
    "accept_specialist_handoff",
    "review_with_skeptic",
    "audit_and_approve_handoff",
    "execute_triad_handoff_workflow",
]
