"""Specialist routing and bounded workflow handoffs.

Implements structured task and evidence handoffs between Planner, Specialist,
Skeptic, and Auditor with accountable execution ownership, capability verification,
evidence consistency validation, and authorization expansion prevention.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from cops.contracts.models import ActionPlan, Engagement, SpecialistHandoff
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import utc_now

from .catalog import get_specialist
from .classifier import route_request


class HandoffError(ValueError):
    """Base exception for workflow handoff errors."""


class MissingCapabilityError(HandoffError):
    """Raised when a routed specialist lacks a required capability, skill, or tool."""


class ConflictingEvidenceError(HandoffError):
    """Raised when evidence envelopes contain contradictory observations or corrupted digests."""


class InvalidHandoffResultError(HandoffError):
    """Raised when handoff deliverables or result payloads fail validation."""


class AuthorizationExpansionError(HandoffError):
    """Raised when a task or handoff attempts to modify material plan fields without re-approval."""


class MaterialPlanModifiedError(AuthorizationExpansionError):
    """Raised when targets, operations, versions, or effects diverge from the approved plan."""


def compute_material_plan_digest(
    target: str,
    operations: list[dict[str, Any]] | list[Any],
    specialist_id: str,
    operator: str,
    allowed_effects: list[str] | None = None,
    limits: dict[str, Any] | None = None,
) -> str:
    """Compute a deterministic SHA-256 digest of material plan fields.

    Material fields: target, operations (step_id, tool, action, arguments),
    specialist_id, operator, allowed_effects, limits.
    """
    normalized_ops = []
    for op in operations:
        if isinstance(op, dict):
            normalized_ops.append({
                "step_id": op.get("step_id", ""),
                "tool": op.get("tool", ""),
                "action": op.get("action", ""),
                "arguments": op.get("arguments", {}),
            })
        else:
            normalized_ops.append(str(op))

    normalized = {
        "allowed_effects": sorted(allowed_effects) if allowed_effects else [],
        "limits": limits or {},
        "operations": normalized_ops,
        "operator": operator.strip(),
        "specialist_id": specialist_id.strip(),
        "target": target.strip(),
    }
    canonical_repr = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def propose_specialist_handoff(
    engagement: Engagement | dict[str, Any],
    action_plan: ActionPlan | dict[str, Any],
    task_description: str,
    sender_id: str,
    *,
    specialist_id: str | None = None,
    required_capabilities: list[str] | None = None,
    operations: list[dict[str, Any]] | None = None,
    deliverable: str | None = None,
    handoff_id: str | None = None,
    registry_path: Path | None = None,
) -> SpecialistHandoff:
    """Create a proposed handoff from planner to a routed specialist.

    Proposals are reported separately from accepted handoffs and execution.
    """
    eng_dict = engagement.to_dict() if isinstance(engagement, Engagement) else engagement
    plan_dict = action_plan.to_dict() if isinstance(action_plan, ActionPlan) else action_plan

    eng_id = eng_dict.get("engagement_id", "")
    plan_id = plan_dict.get("plan_id", "")
    operator = eng_dict.get("operator", sender_id)
    target = plan_dict.get("target", "")

    # Resolve specialist profile
    if specialist_id is None:
        decision = route_request(task_description, registry_path=registry_path)
        selected_specialist = decision.selected_profile.id
    else:
        selected_specialist = specialist_id

    # Verify specialist exists in catalog
    profile = get_specialist(selected_specialist, registry_path=registry_path)

    # Determine operations and required capabilities
    plan_ops = operations if operations is not None else plan_dict.get("operations", [])
    req_caps = list(required_capabilities) if required_capabilities is not None else []
    if not req_caps:
        # Default required capabilities to specialist's primary skill or task keywords
        req_caps = list(profile.skills[:1]) if profile.skills else ["general-assessment"]

    # Compute material plan digest
    allowed = eng_dict.get("rules_of_engagement", {}).get("allowed_actions", [])
    limits = plan_dict.get("limits", {})
    material_digest = compute_material_plan_digest(
        target=target,
        operations=plan_ops,
        specialist_id=selected_specialist,
        operator=operator,
        allowed_effects=allowed,
        limits=limits,
    )

    # Check if plan status is approved
    plan_status = plan_dict.get("status", "draft")
    approval_status = "approved" if plan_status == "approved" else "pending"

    now_iso = utc_now()
    h_id = handoff_id or f"hnd-{uuid.uuid4().hex[:12]}"

    initial_log = [{
        "from_status": "none",
        "to_status": "proposed",
        "actor": sender_id,
        "timestamp": now_iso,
        "notes": f"Proposal created for specialist {selected_specialist}",
    }]

    handoff = SpecialistHandoff(
        schema_version="cops.specialist-handoff/v1",
        handoff_id=h_id,
        engagement_id=eng_id,
        action_plan_id=plan_id,
        status="proposed",
        sender={"role": "planner", "identifier": sender_id},
        recipient={"role": "specialist", "specialist_id": selected_specialist},
        task={
            "task_description": task_description,
            "target": target,
            "required_capabilities": req_caps,
            "operations": plan_ops,
            "deliverable": deliverable or f"Technical findings and verification evidence for {target}",
        },
        material_plan_digest=material_digest,
        approval_status=approval_status,
        created_at=now_iso,
        transition_log=initial_log,
        evidence={"evidence_envelopes": [], "findings": []},
    )

    validate_contract(handoff.to_dict(), "specialist_handoff")
    return handoff


def accept_specialist_handoff(
    handoff: SpecialistHandoff,
    specialist_id: str,
    *,
    registry_path: Path | None = None,
) -> SpecialistHandoff:
    """Specialist accepts a proposed handoff after verifying capability coverage."""
    if handoff.status != "proposed":
        raise HandoffError(f"Cannot accept handoff in status '{handoff.status}', expected 'proposed'")

    if handoff.recipient.get("specialist_id") != specialist_id:
        raise HandoffError(
            f"Specialist '{specialist_id}' does not match handoff recipient '{handoff.recipient.get('specialist_id')}'"
        )

    profile = get_specialist(specialist_id, registry_path=registry_path)

    # Check required capabilities
    required = handoff.task.get("required_capabilities", [])
    available_capabilities = (
        set(profile.skills)
        | set(profile.tools)
        | {profile.primary_plugin}
        | set(profile.intent_keywords)
        | {profile.domain}
    )
    # Match capabilities: each required capability must be contained or substring-matched in profile
    missing = []
    for req in required:
        req_norm = req.lower().replace("-", " ").replace("_", " ")
        matched = False
        for cap in available_capabilities:
            cap_norm = cap.lower().replace("-", " ").replace("_", " ")
            if req.lower() in cap.lower() or req_norm in cap_norm:
                matched = True
                break
        if not matched:
            missing.append(req)

    if missing:
        handoff.transition_to(
            "rejected",
            actor=specialist_id,
            notes=f"Missing required capabilities: {missing}",
        )
        handoff.rejection_reason = f"Specialist lacks required capabilities: {missing}"
        raise MissingCapabilityError(f"Specialist '{specialist_id}' lacks required capabilities: {missing}")

    handoff.transition_to(
        "accepted",
        actor=specialist_id,
        notes=f"Accepted by {specialist_id} with full capability coverage",
    )
    validate_contract(handoff.to_dict(), "specialist_handoff")
    return handoff


def review_with_skeptic(
    handoff: SpecialistHandoff,
    skeptic_id: str,
    *,
    evidence_envelopes: list[dict[str, Any]] | list[str] | None = None,
    findings: list[str] | None = None,
    contradictory_evidence: list[dict[str, Any]] | None = None,
    objection: str | None = None,
    registry_path: Path | None = None,
) -> SpecialistHandoff:
    """Domain Skeptic reviews candidate evidence envelopes and findings for conflicts and false claims."""
    if handoff.status != "accepted":
        raise HandoffError(f"Cannot perform skeptic review on handoff in status '{handoff.status}', expected 'accepted'")

    # Verify skeptic exists
    get_specialist(skeptic_id, registry_path=registry_path)

    # Detect conflicting evidence or objections
    if objection:
        handoff.transition_to("rejected", actor=skeptic_id, notes=f"Skeptic objection: {objection}")
        handoff.rejection_reason = f"Skeptic objection: {objection}"
        raise ConflictingEvidenceError(f"Skeptic '{skeptic_id}' rejected evidence: {objection}")

    if contradictory_evidence:
        reason = "Contradictory evidence detected in submitted telemetry envelopes"
        handoff.transition_to("rejected", actor=skeptic_id, notes=reason)
        handoff.rejection_reason = reason
        raise ConflictingEvidenceError(reason)

    # Inspect submitted evidence envelopes
    env_refs: list[str] = []
    if evidence_envelopes:
        observed_facts: dict[str, Any] = {}
        for env in evidence_envelopes:
            if isinstance(env, dict):
                ref = env.get("envelope_id") or env.get("ref", f"env-{uuid.uuid4().hex[:8]}")
                env_refs.append(ref)
                # Check for contradictory status assertions on the same subject
                subject = env.get("subject") or env.get("target")
                fact = env.get("fact") or env.get("observed_state")
                if subject and fact:
                    if subject in observed_facts and observed_facts[subject] != fact:
                        reason = f"Conflicting observations for subject '{subject}': '{observed_facts[subject]}' vs '{fact}'"
                        handoff.transition_to("rejected", actor=skeptic_id, notes=reason)
                        handoff.rejection_reason = reason
                        raise ConflictingEvidenceError(reason)
                    observed_facts[subject] = fact
            elif isinstance(env, str):
                env_refs.append(env)

    # Attach verified evidence to handoff
    current_evidence = handoff.evidence or {}
    updated_envelopes = list(set(current_evidence.get("evidence_envelopes", []) + env_refs))
    updated_findings = list(set(current_evidence.get("findings", []) + (findings or [])))

    handoff.evidence = {
        "evidence_envelopes": updated_envelopes,
        "findings": updated_findings,
        "notes": f"Reviewed and verified by skeptic {skeptic_id}",
    }

    handoff.transition_to(
        "in_review",
        actor=skeptic_id,
        notes=f"Skeptic review passed by {skeptic_id}",
    )
    validate_contract(handoff.to_dict(), "specialist_handoff")
    return handoff


def audit_and_approve_handoff(
    handoff: SpecialistHandoff,
    auditor_id: str,
    approved_action_plan: ActionPlan | dict[str, Any],
    *,
    candidate_target: str | None = None,
    candidate_operations: list[dict[str, Any]] | None = None,
    candidate_operator: str | None = None,
    candidate_allowed_effects: list[str] | None = None,
    candidate_limits: dict[str, Any] | None = None,
    registry_path: Path | None = None,
) -> SpecialistHandoff:
    """Auditor validates plan bounds, enforces authorization invariance, and marks handoff complete."""
    if handoff.status != "in_review":
        raise HandoffError(f"Cannot audit handoff in status '{handoff.status}', expected 'in_review'")

    # Verify auditor exists
    get_specialist(auditor_id, registry_path=registry_path)

    plan_dict = approved_action_plan.to_dict() if isinstance(approved_action_plan, ActionPlan) else approved_action_plan
    approved_target = plan_dict.get("target", "").strip()
    approved_ops = plan_dict.get("operations", [])

    # 1. Target scope expansion check
    check_target = (candidate_target or handoff.task.get("target", "")).strip()
    if check_target != approved_target:
        reason = f"Attempted authorization expansion: target '{check_target}' differs from approved plan target '{approved_target}'"
        handoff.approval_status = "reapproval_required"
        handoff.transition_to("rejected", actor=auditor_id, notes=reason)
        handoff.rejection_reason = reason
        raise AuthorizationExpansionError(reason)

    # 2. Operations expansion check
    check_ops = candidate_operations if candidate_operations is not None else handoff.task.get("operations", [])
    approved_tools = {op.get("tool") for op in approved_ops if isinstance(op, dict)}
    for op in check_ops:
        if isinstance(op, dict):
            tool = op.get("tool")
            if tool and approved_tools and tool not in approved_tools:
                reason = f"Attempted authorization expansion: unapproved tool '{tool}' not declared in approved action plan"
                handoff.approval_status = "reapproval_required"
                handoff.transition_to("rejected", actor=auditor_id, notes=reason)
                handoff.rejection_reason = reason
                raise AuthorizationExpansionError(reason)

    # 3. Material plan modification check
    sender_operator = handoff.sender.get("identifier", "").strip()
    material_modified = False

    if candidate_operator is not None and candidate_operator.strip() != sender_operator:
        material_modified = True
    if candidate_operations is not None and candidate_operations != approved_ops:
        material_modified = True
    if candidate_allowed_effects is not None:
        material_modified = True
    if candidate_limits is not None and candidate_limits != plan_dict.get("limits", {}):
        material_modified = True
    if check_ops != approved_ops:
        material_modified = True
    if handoff.approval_status == "reapproval_required":
        material_modified = True

    if material_modified:
        reason = "Material plan field changed; reapproval is required before execution."
        handoff.approval_status = "reapproval_required"
        handoff.transition_to("rejected", actor=auditor_id, notes=reason)
        handoff.rejection_reason = reason
        raise MaterialPlanModifiedError(reason)

    # 4. Deliverable validation
    deliverable = handoff.task.get("deliverable")
    if not deliverable or not isinstance(deliverable, str) or not deliverable.strip():
        reason = "Handoff deliverable is empty or missing"
        handoff.transition_to("rejected", actor=auditor_id, notes=reason)
        handoff.rejection_reason = reason
        raise InvalidHandoffResultError(reason)

    # Mark completed and approved
    handoff.approval_status = "approved"
    handoff.transition_to(
        "completed",
        actor=auditor_id,
        notes=f"Audited and approved by {auditor_id}",
    )
    validate_contract(handoff.to_dict(), "specialist_handoff")
    return handoff


def execute_triad_handoff_workflow(
    engagement: Engagement | dict[str, Any],
    action_plan: ActionPlan | dict[str, Any],
    task_description: str,
    planner_id: str,
    *,
    specialist_id: str | None = None,
    skeptic_id: str | None = None,
    auditor_id: str | None = None,
    evidence_envelopes: list[dict[str, Any]] | None = None,
    findings: list[str] | None = None,
    registry_path: Path | None = None,
) -> SpecialistHandoff:
    """Orchestrate the complete Triad handoff workflow from proposal to audited handoff."""
    # 1. Propose handoff
    handoff = propose_specialist_handoff(
        engagement=engagement,
        action_plan=action_plan,
        task_description=task_description,
        sender_id=planner_id,
        specialist_id=specialist_id,
        registry_path=registry_path,
    )

    spec_id = handoff.recipient["specialist_id"]
    profile = get_specialist(spec_id, registry_path=registry_path)
    triad_defaults = profile.triad_defaults or {}
    resolved_skeptic = skeptic_id or triad_defaults.get("skeptic_profile_id", "cops-threat-hunter")
    resolved_auditor = auditor_id or triad_defaults.get("auditor_profile_id", "cops-compliance-auditor")

    # 2. Specialist acceptance
    accept_specialist_handoff(handoff, spec_id, registry_path=registry_path)

    # 3. Skeptic review
    review_with_skeptic(
        handoff,
        resolved_skeptic,
        evidence_envelopes=evidence_envelopes,
        findings=findings,
        registry_path=registry_path,
    )

    # 4. Auditor audit & approve
    audit_and_approve_handoff(
        handoff,
        resolved_auditor,
        action_plan,
        registry_path=registry_path,
    )

    return handoff
