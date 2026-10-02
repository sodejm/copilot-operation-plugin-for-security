"""Triad orchestration assembly for high-risk and critical cybersecurity tasks."""

from __future__ import annotations

from pathlib import Path

from .catalog import get_specialist
from .models import SpecialistProfile, TriadExecutionPlan, TriadMember


def assemble_triad_plan(
    primary_profile: SpecialistProfile,
    task_description: str,
    registry_path: Path | None = None,
) -> TriadExecutionPlan:
    """Construct a three-agent Triad execution plan for critical tasks."""
    defaults = primary_profile.triad_defaults or {}
    skeptic_id = defaults.get("skeptic_profile_id", "cops-threat-hunter")
    auditor_id = defaults.get("auditor_profile_id", "cops-compliance-auditor")

    skeptic_profile = get_specialist(skeptic_id, registry_path)
    auditor_profile = get_specialist(auditor_id, registry_path)

    # Focus descriptions tailored to the domain
    if primary_profile.domain == "offensive-security":
        primary_focus = "Execute scoped offensive review, model adversary transitions, and draft vulnerability POCs."
        skeptic_focus = "Challenge attack prerequisites, test defensive detection viability, and verify RoE boundaries."
        auditor_focus = "Verify cryptographically signed RoE authorization receipt and audit scope compliance."
    elif primary_profile.domain == "incident-forensics":
        primary_focus = "Model incident blast radius, plan containment actions, and specify rollback steps."
        skeptic_focus = "Challenge containment dependencies, identify collateral operational impact, and test alternatives."
        auditor_focus = "Verify chain of custody, ensure evidence capture precedes containment, and audit authorization."
    elif primary_profile.domain == "identity-exposure":
        primary_focus = "Analyze identity entitlement graphs, identify toxic combinations, and trace escalation paths."
        skeptic_focus = "Verify structural feasibility of claimed escalation paths against actual tenant constraints."
        auditor_focus = "Verify least-privilege evidence hashes and compliance policy alignment."
    else:
        primary_focus = "Execute core analytical investigation and formulate primary findings."
        skeptic_focus = "Challenge assumptions, evaluate benign alternative hypotheses, and check for confirmation bias."
        auditor_focus = "Verify tamper-evident evidence envelope hashes and ensure reproducible data contracts."

    primary_member = TriadMember(
        role="primary",
        specialist_id=primary_profile.id,
        display_name=primary_profile.display_name,
        review_focus=primary_focus,
        deliverable="Draft finding or operational plan with candidate entity transitions.",
    )
    skeptic_member = TriadMember(
        role="skeptic",
        specialist_id=skeptic_profile.id,
        display_name=skeptic_profile.display_name,
        review_focus=skeptic_focus,
        deliverable="Formal skepticism review citing disputed transitions, edge cases, and benign alternatives.",
    )
    auditor_member = TriadMember(
        role="auditor",
        specialist_id=auditor_profile.id,
        display_name=auditor_profile.display_name,
        review_focus=auditor_focus,
        deliverable="Cryptographic evidence audit stamp or material objection blocking publication.",
    )

    handoff_steps = (
        f"1. Task received: Router assigns Primary Specialist ({primary_profile.id}).",
        f"2. Primary executes deterministic offline tooling and drafts initial findings/plan.",
        f"3. Primary hands candidate artifact to Domain Skeptic ({skeptic_profile.id}) to critique assumptions.",
        f"4. Skeptic reviews transitions; disputed claims are labeled 'candidate' or 'invalid'.",
        f"5. Primary and Skeptic submit reconciled package to Evidence Auditor ({auditor_profile.id}).",
        f"6. Auditor verifies SHA-256 evidence envelopes and operator authorization receipt.",
        f"7. Auditor seals and issues the final, tamper-evident deliverable.",
    )

    return TriadExecutionPlan(
        task_description=task_description,
        criticality="critical",
        primary=primary_member,
        skeptic=skeptic_member,
        auditor=auditor_member,
        handoff_steps=handoff_steps,
    )
