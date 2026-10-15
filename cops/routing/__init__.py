"""COPS Specialist Agent Profiles and Dynamic Routing Engine."""

from .catalog import get_specialist, load_specialists_registry
from .classifier import ClassifierRequest, ClassifierResponse, OptionalClassifier, route_request
from .features import RoutingFeatures, extract_routing_features
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
from .models import RoutingCandidate, RoutingDecision, SpecialistProfile, TriadExecutionPlan, TriadMember
from .triad import assemble_triad_plan

__all__ = [
    "SpecialistProfile",
    "TriadMember",
    "TriadExecutionPlan",
    "RoutingDecision",
    "RoutingCandidate",
    "RoutingFeatures",
    "extract_routing_features",
    "ClassifierRequest",
    "ClassifierResponse",
    "OptionalClassifier",
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
