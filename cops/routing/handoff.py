"""Specialist routing and bounded workflow handoffs.

Implements structured task and evidence handoffs between Planner, Specialist,
Skeptic, and Auditor with accountable execution ownership, capability verification,
evidence consistency validation, and authorization expansion prevention.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

from cops.contracts.models import ActionPlan, Engagement, SpecialistHandoff
from cops.contracts.validation import validate_contract, workflow_target_checksum
from cops.evidence.canonical import utc_now

from .catalog import ROOT, SpecialistCatalogError, get_specialist
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


_SKILL_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _resolve_workflow_target(
    target: Any,
    specialist_id: str,
    *,
    registry_path: Path | None = None,
) -> dict[str, str]:
    """Resolve a declared workflow to a registered capability and local skill file."""
    if not isinstance(target, dict):
        raise MissingCapabilityError("Handoff has no workflow target")

    skill_id = target.get("skill_id")
    capability_id = target.get("capability_id")
    if not isinstance(skill_id, str) or not _SKILL_ID.fullmatch(skill_id):
        raise MissingCapabilityError(f"Invalid workflow skill identifier: {skill_id!r}")
    if not isinstance(capability_id, str) or capability_id != specialist_id:
        raise MissingCapabilityError("Workflow capability does not match the recipient specialist")

    try:
        profile = get_specialist(specialist_id, registry_path=registry_path)
    except SpecialistCatalogError as err:
        raise MissingCapabilityError(f"Workflow recipient '{specialist_id}' is unavailable") from err
    if skill_id not in profile.skills:
        raise MissingCapabilityError(f"Workflow skill '{skill_id}' is not declared by '{specialist_id}'")

    root = registry_path.resolve().parent.parent if registry_path is not None else ROOT
    capabilities_file = root / "catalog" / "capabilities.json"
    try:
        capabilities = json.loads(capabilities_file.read_text(encoding="utf-8"))["capabilities"]
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise MissingCapabilityError("Capability catalog is unavailable or invalid") from err
    if not isinstance(capabilities, list) or not any(
        isinstance(item, dict) and item.get("id") == capability_id and item.get("kind") == "specialist"
        for item in capabilities
    ):
        raise MissingCapabilityError(f"Workflow capability '{capability_id}' is not registered as a specialist")

    skills_root = (root / ".agents" / "skills").resolve()
    skill_file = root / ".agents" / "skills" / skill_id / "SKILL.md"
    if not skill_file.resolve().is_relative_to(skills_root) or not skill_file.is_file():
        raise MissingCapabilityError(f"Workflow skill '{skill_id}' has no local implementation")
    try:
        content = skill_file.read_bytes()
        lines = content.decode("utf-8").splitlines()
    except (OSError, UnicodeError) as err:
        raise MissingCapabilityError(f"Workflow skill '{skill_id}' cannot be read") from err
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        raise MissingCapabilityError(f"Workflow skill '{skill_id}' has invalid frontmatter")
    frontmatter = lines[1 : lines[1:].index("---") + 1]
    names = []
    for line in frontmatter:
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip() == "name":
                names.append(value.strip().strip("\"'"))
    if names != [skill_id]:
        raise MissingCapabilityError(f"Workflow skill '{skill_id}' has a mismatched frontmatter name")

    return {
        "skill_id": skill_id,
        "capability_id": capability_id,
        "implementation": f".agents/skills/{skill_id}/SKILL.md",
        "implementation_digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
    }


def _reject_missing_workflow_target(handoff: SpecialistHandoff, actor: str, reason: str) -> None:
    handoff.transition_to("rejected", actor=actor, notes=reason)
    handoff.rejection_reason = reason


def _verify_workflow_target(handoff: SpecialistHandoff, *, registry_path: Path | None = None) -> None:
    """Check record consistency and resolve its workflow against the current checkout."""
    accepted_entries = [entry for entry in handoff.transition_log if entry.get("to_status") == "accepted"]
    target = handoff.task.get("workflow_target")
    if (
        not isinstance(target, dict)
        or len(accepted_entries) != 1
        or accepted_entries[0].get("workflow_target_checksum") != workflow_target_checksum(target)
    ):
        raise MissingCapabilityError("Workflow target checksum differs from the accepted transition")
    resolved_target = _resolve_workflow_target(
        target,
        handoff.recipient["specialist_id"],
        registry_path=registry_path,
    )
    if target != resolved_target:
        raise MissingCapabilityError("Workflow target differs from the current local implementation")


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
            normalized_ops.append(
                {
                    "step_id": op.get("step_id", ""),
                    "tool": op.get("tool", ""),
                    "action": op.get("action", ""),
                    "arguments": op.get("arguments", {}),
                }
            )
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
    workflow_skill_id: str | None = None,
    capability_id: str | None = None,
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

    if (workflow_skill_id is None) != (capability_id is None):
        raise HandoffError("Both workflow_skill_id and capability_id are required to declare a workflow target")

    # Determine operations and required capabilities
    plan_ops = operations if operations is not None else plan_dict.get("operations", [])
    req_caps = list(required_capabilities) if required_capabilities is not None else []
    if not req_caps:
        # Default required capabilities to specialist's primary skill or task keywords
        req_caps = (
            [workflow_skill_id]
            if workflow_skill_id
            else (list(profile.skills[:1]) if profile.skills else ["general-assessment"])
        )

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

    initial_log = [
        {
            "from_status": "none",
            "to_status": "proposed",
            "actor": sender_id,
            "timestamp": now_iso,
            "notes": f"Proposal created for specialist {selected_specialist}",
        }
    ]

    task = {
        "task_description": task_description,
        "target": target,
        "required_capabilities": req_caps,
        "operations": plan_ops,
        "deliverable": deliverable or f"Technical findings and verification evidence for {target}",
    }
    if workflow_skill_id is not None:
        task["workflow_target"] = {"skill_id": workflow_skill_id, "capability_id": capability_id}

    handoff = SpecialistHandoff(
        schema_version="cops.specialist-handoff/v1",
        handoff_id=h_id,
        engagement_id=eng_id,
        action_plan_id=plan_id,
        status="proposed",
        sender={"role": "planner", "identifier": sender_id},
        recipient={"role": "specialist", "specialist_id": selected_specialist},
        task=task,
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

    try:
        profile = get_specialist(specialist_id, registry_path=registry_path)
    except SpecialistCatalogError as err:
        reason = f"Workflow recipient '{specialist_id}' is unavailable"
        _reject_missing_workflow_target(handoff, specialist_id, reason)
        raise MissingCapabilityError(reason) from err

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

    try:
        resolved_target = _resolve_workflow_target(
            handoff.task.get("workflow_target"),
            specialist_id,
            registry_path=registry_path,
        )
    except MissingCapabilityError as err:
        _reject_missing_workflow_target(handoff, specialist_id, str(err))
        raise
    handoff.task["workflow_target"] = resolved_target

    handoff.transition_to(
        "accepted",
        actor=specialist_id,
        notes=f"Accepted by {specialist_id} with full capability coverage",
    )
    handoff.transition_log[-1]["workflow_target_checksum"] = workflow_target_checksum(resolved_target)
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
        raise HandoffError(
            f"Cannot perform skeptic review on handoff in status '{handoff.status}', expected 'accepted'"
        )

    try:
        _verify_workflow_target(handoff, registry_path=registry_path)
    except MissingCapabilityError as err:
        _reject_missing_workflow_target(handoff, skeptic_id, str(err))
        raise

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
                        reason = (
                            f"Conflicting observations for subject '{subject}': '{observed_facts[subject]}' vs '{fact}'"
                        )
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

    try:
        _verify_workflow_target(handoff, registry_path=registry_path)
    except MissingCapabilityError as err:
        _reject_missing_workflow_target(handoff, auditor_id, str(err))
        raise

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
                reason = (
                    f"Attempted authorization expansion: unapproved tool '{tool}' not declared in approved action plan"
                )
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

    try:
        _verify_workflow_target(handoff, registry_path=registry_path)
    except MissingCapabilityError as err:
        _reject_missing_workflow_target(handoff, auditor_id, str(err))
        raise

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
    workflow_skill_id: str | None = None,
    capability_id: str | None = None,
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
        workflow_skill_id=workflow_skill_id,
        capability_id=capability_id,
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
