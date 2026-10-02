"""Deterministic, zero-token intent classifier for routing security tasks to specialist agents."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from .catalog import load_specialists_registry
from .models import RoutingDecision, SpecialistProfile
from .triad import assemble_triad_plan


def _tokenize(text: str) -> set[str]:
    """Extract normalized alphanumeric word tokens."""
    return set(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", text.lower()))


def route_request(
    query: str,
    *,
    registry_path: Path | None = None,
    force_critical: bool = False,
) -> RoutingDecision:
    """Classify a security request and select the best specialist profile.

    Runs entirely on host CPU using Python standard library regex and scoring heuristics;
    consumes zero model tokens and avoids non-deterministic hallucinations.
    """
    profiles = load_specialists_registry(registry_path)
    clean_query = query.strip()
    query_lower = clean_query.lower()
    query_tokens = _tokenize(query_lower)

    # Check for direct profile ID mention
    for profile in profiles:
        clean_id = profile.id.lower()
        short_id = clean_id.removeprefix("cops-")
        if clean_id in query_lower or short_id in query_lower or f"@{short_id}" in query_lower:
            is_critical = profile.is_critical or force_critical
            triad_plan = assemble_triad_plan(profile, clean_query, registry_path) if is_critical else None
            return RoutingDecision(
                query=clean_query,
                primary_profile=profile,
                confidence=0.99,
                match_reasons=(f"Direct profile match for '{profile.id}' in request",),
                criticality="critical" if is_critical else "normal",
                interactive_authorization_required=profile.interactive_authorization_required,
                recommended_skills=profile.skills,
                triad_plan=triad_plan,
            )

    scored_profiles: list[tuple[float, list[str], SpecialistProfile]] = []

    for profile in profiles:
        score = 0.0
        reasons: list[str] = []

        # 1. Multi-word phrase matches (highest signal)
        for keyword in profile.intent_keywords:
            if " " in keyword and keyword in query_lower:
                score += 4.0
                reasons.append(f"Matched phrase '{keyword}' (+4.0)")

        # 2. Single token matches
        for keyword in profile.intent_keywords:
            if " " not in keyword:
                if keyword in query_tokens:
                    score += 1.5
                    reasons.append(f"Matched keyword '{keyword}' (+1.5)")

        # 3. Tool and skill name matches
        for skill in profile.skills:
            if skill.lower() in query_tokens or skill.lower() in query_lower:
                score += 3.0
                reasons.append(f"Matched skill capability '{skill}' (+3.0)")

        for tool in profile.tools:
            if tool.lower() in query_lower:
                score += 2.0
                reasons.append(f"Matched tool capability '{tool}' (+2.0)")

        if score > 0:
            scored_profiles.append((score, reasons, profile))

    if scored_profiles:
        # Sort by score descending
        scored_profiles.sort(key=lambda item: item[0], reverse=True)
        top_score, top_reasons, best_profile = scored_profiles[0]

        # Calculate normalized confidence (clamped 0.50 to 0.98)
        confidence = min(0.98, max(0.50, 0.40 + (top_score / 10.0)))
        reasons_tuple = tuple(top_reasons)
    else:
        # Default fallback to General SOC Analyst triage
        best_profile = next(p for p in profiles if p.id == "cops-soc-analyst")
        confidence = 0.35
        reasons_tuple = ("Default general security triage fallback (no specific profile keywords identified)",)

    is_critical = best_profile.is_critical or force_critical
    triad_plan = assemble_triad_plan(best_profile, clean_query, registry_path) if is_critical else None

    return RoutingDecision(
        query=clean_query,
        primary_profile=best_profile,
        confidence=confidence,
        match_reasons=reasons_tuple,
        criticality="critical" if is_critical else "normal",
        interactive_authorization_required=best_profile.interactive_authorization_required,
        recommended_skills=best_profile.skills,
        triad_plan=triad_plan,
    )
