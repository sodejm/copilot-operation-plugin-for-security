"""Deterministic specialist routing with fail-closed optional classification."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from typing import Protocol

from .catalog import load_specialists_registry
from .features import RoutingFeatures, extract_routing_features
from .models import RoutingCandidate, RoutingDecision, SpecialistProfile
from .triad import assemble_triad_plan

MIN_ROUTE_CONFIDENCE = 0.65
MIN_LEAD_GAP = 0.15


@dataclass(frozen=True)
class ClassifierRequest:
    """Privacy-preserving input for an explicitly configured optional classifier."""

    model: str
    deadline_ms: int
    token_budget: int
    features: dict[str, object]
    registered_specialist_ids: tuple[str, ...]


@dataclass(frozen=True)
class ClassifierResponse:
    """A classifier's bounded selection from the registered identifiers."""

    specialist_id: str
    confidence: float
    reason: str = "Optional classifier selected a registered specialist"
    tokens_used: int = 0


class OptionalClassifier(Protocol):
    def __call__(self, request: ClassifierRequest) -> ClassifierResponse: ...


def _bounded_classification(classifier: OptionalClassifier, request: ClassifierRequest) -> ClassifierResponse:
    """Bound caller latency even if an adapter ignores its provider deadline.

    Adapters must also enforce the supplied deadline and token budget at the
    provider. Python cannot forcibly cancel a provider call in another thread;
    late results are discarded and never authorize or execute an action.
    """
    result: Queue[object] = Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put(classifier(request))
        except Exception:
            result.put(None)

    Thread(target=invoke, name="cops-optional-classifier", daemon=True).start()
    try:
        value = result.get(timeout=request.deadline_ms / 1000)
    except Empty:
        raise TimeoutError from None
    if not isinstance(value, ClassifierResponse):
        raise ValueError("invalid_classifier_response")
    return value


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", text.lower()))


def _triggers(profile: SpecialistProfile) -> tuple[str, ...]:
    return profile.symptom_triggers or profile.intent_keywords


def _document_terms(profile: SpecialistProfile) -> tuple[str, ...]:
    parts = (
        *_triggers(profile),
        *profile.artifact_triggers,
        *profile.example_prompts,
        profile.domain,
        profile.description,
        *profile.skills,
        *profile.tools,
    )
    return _tokens(" ".join(parts))


def _bm25_scores(query_tokens: tuple[str, ...], profiles: list[SpecialistProfile]) -> dict[str, float]:
    """Return standard BM25 relevance scores over the registered profile corpus."""
    documents = {profile.id: _document_terms(profile) for profile in profiles}
    lengths = {profile_id: len(terms) for profile_id, terms in documents.items()}
    average_length = sum(lengths.values()) / max(1, len(lengths))
    document_frequency: Counter[str] = Counter()
    for terms in documents.values():
        document_frequency.update(set(terms))

    scores: dict[str, float] = {}
    query_counts = Counter(query_tokens)
    for profile_id, terms in documents.items():
        term_counts = Counter(terms)
        score = 0.0
        for term, query_frequency in query_counts.items():
            frequency = term_counts[term]
            if not frequency:
                continue
            inverse_frequency = math.log(
                1.0 + (len(documents) - document_frequency[term] + 0.5) / (document_frequency[term] + 0.5)
            )
            denominator = frequency + 1.2 * (1.0 - 0.75 + 0.75 * lengths[profile_id] / average_length)
            score += query_frequency * inverse_frequency * frequency * 2.2 / denominator
        scores[profile_id] = score
    return scores


def _fuzzy_score(query: str, trigger: str) -> float:
    """Conservatively match a trigger against same-sized query word windows."""
    trigger_tokens = _tokens(trigger)
    query_tokens = _tokens(query)
    if not trigger_tokens or len(trigger_tokens) > len(query_tokens):
        return 0.0
    width = len(trigger_tokens)
    target = " ".join(trigger_tokens)
    ratio = max(
        SequenceMatcher(None, target, " ".join(query_tokens[index : index + width])).ratio()
        for index in range(len(query_tokens) - width + 1)
    )
    return ratio if ratio >= 0.88 else 0.0


def _candidate_scores(
    query: str,
    profiles: list[SpecialistProfile],
    features: RoutingFeatures,
) -> list[RoutingCandidate]:
    query_lower = query.lower()
    query_tokens = set(_tokens(query))
    feature_labels = set(features.labels)
    bm25 = _bm25_scores(_tokens(query), profiles)
    raw: list[tuple[float, list[str], SpecialistProfile]] = []

    for profile in profiles:
        score = min(5.0, bm25[profile.id])
        reasons: list[str] = []
        if score >= 0.75:
            reasons.append(f"BM25 relevance {score:.2f}")

        for trigger in _triggers(profile):
            lowered = trigger.lower()
            if lowered in query_lower:
                # A complete multi-word canonical symptom is sufficient evidence
                # to clear the default confidence threshold even in a one-profile
                # registry. Single words remain supporting evidence only.
                weight = 8.0 if " " in lowered else 2.5
                score += weight
                reasons.append(f"Matched symptom trigger '{trigger}'")
            elif len(lowered) >= 5:
                ratio = _fuzzy_score(query_lower, lowered)
                if ratio:
                    score += 2.0 * ratio
                    reasons.append(f"Fuzzy symptom trigger '{trigger}' ({ratio:.2f})")

        for trigger in profile.artifact_triggers:
            lowered = trigger.lower()
            normalized = lowered.replace(" ", "_").replace("-", "_")
            if lowered in query_lower or lowered in query_tokens or normalized in feature_labels:
                score += 8.0
                reasons.append(f"Matched artifact trigger '{trigger}'")

        for example in profile.example_prompts:
            if example.strip().lower() == query_lower:
                score += 8.0
                reasons.append("Matched a published example prompt")

        for trigger in profile.anti_triggers:
            lowered = trigger.lower()
            if lowered in query_lower:
                score -= 8.0
                reasons.append(f"Applied anti-trigger '{trigger}'")

        if score > 0.25 and reasons:
            raw.append((score, reasons, profile))

    raw.sort(key=lambda item: (-item[0], item[2].id))
    candidates: list[RoutingCandidate] = []
    for score, reasons, profile in raw:
        confidence = max(0.0, min(0.98, 1.0 - math.exp(-score / 7.0)))
        candidates.append(RoutingCandidate(profile=profile, confidence=confidence, score=score, reasons=tuple(reasons)))
    return candidates


def _clarification(query: str, candidates: list[RoutingCandidate], reason: str) -> RoutingDecision:
    shortlist = candidates[:3]
    return RoutingDecision(
        query=query,
        primary_profile=None,
        confidence=shortlist[0].confidence if shortlist else 0.0,
        match_reasons=(reason,),
        criticality="unknown",
        interactive_authorization_required=False,
        recommended_skills=(),
        status="clarification_required",
        ranked_candidates=tuple(shortlist),
        clarification={
            "reason": reason,
            "question": "Which specialist purpose and permission scope match the intended outcome?",
            "options": [
                {
                    "specialist_id": candidate.profile.id,
                    "purpose": candidate.profile.purpose or candidate.profile.description,
                    "required_permissions": list(candidate.profile.required_permissions),
                    "interactive_authorization_required": candidate.profile.interactive_authorization_required,
                }
                for candidate in shortlist
            ],
        },
    )


def _routed(
    query: str,
    candidate: RoutingCandidate,
    candidates: list[RoutingCandidate],
    registry_path: Path | None,
    force_critical: bool,
) -> RoutingDecision:
    profile = candidate.profile
    is_critical = profile.is_critical or force_critical
    triad_plan = assemble_triad_plan(profile, query, registry_path) if is_critical else None
    return RoutingDecision(
        query=query,
        primary_profile=profile,
        confidence=candidate.confidence,
        match_reasons=candidate.reasons,
        criticality="critical" if is_critical else "normal",
        interactive_authorization_required=profile.interactive_authorization_required,
        recommended_skills=profile.skills,
        triad_plan=triad_plan,
        status="routed",
        ranked_candidates=tuple(candidates[:5]),
    )


def route_request(
    query: str,
    *,
    registry_path: Path | None = None,
    force_critical: bool = False,
    optional_classifier: OptionalClassifier | None = None,
    classifier_model: str | None = None,
    classifier_deadline_ms: int | None = None,
    classifier_token_budget: int | None = None,
) -> RoutingDecision:
    """Route a request or return a reviewable clarification requirement."""
    profiles = load_specialists_registry(registry_path)
    clean_query = query.strip()
    query_lower = clean_query.lower()
    features = extract_routing_features(clean_query)

    for profile in profiles:
        clean_id = profile.id.lower()
        short_id = clean_id.removeprefix("cops-")
        direct_reference = (
            clean_id in _tokens(query_lower)
            or query_lower == short_id
            or re.search(rf"(?<![a-z0-9-])@{re.escape(short_id)}(?![a-z0-9-])", query_lower) is not None
        )
        if direct_reference:
            candidate = RoutingCandidate(
                profile=profile,
                confidence=0.99,
                score=99.0,
                reasons=(f"Direct profile match for '{profile.id}' in request",),
            )
            return _routed(clean_query, candidate, [candidate], registry_path, force_critical)

    candidates = _candidate_scores(clean_query, profiles, features)
    top = candidates[0] if candidates else None
    runner = candidates[1] if len(candidates) > 1 else None
    deterministic_reason: str | None = None
    if top is None or top.confidence < MIN_ROUTE_CONFIDENCE:
        deterministic_reason = "No specialist reached the minimum routing confidence of 0.65"
    elif runner is not None and top.confidence - runner.confidence < MIN_LEAD_GAP:
        deterministic_reason = "The leading specialists are within the minimum confidence gap of 0.15"
    else:
        return _routed(clean_query, top, candidates, registry_path, force_critical)

    if optional_classifier is None:
        return _clarification(clean_query, candidates, deterministic_reason)
    if not classifier_model or classifier_deadline_ms is None or classifier_token_budget is None:
        return _clarification(
            clean_query, candidates, "Optional classifier requires explicit model, deadline, and budget"
        )
    if (
        type(classifier_deadline_ms) is not int or type(classifier_token_budget) is not int
        or classifier_deadline_ms <= 0 or classifier_token_budget <= 0
    ):
        return _clarification(clean_query, candidates, "Optional classifier deadline or budget is exhausted")

    request = ClassifierRequest(
        model=classifier_model,
        deadline_ms=classifier_deadline_ms,
        token_budget=classifier_token_budget,
        features=features.redacted_dict(),
        registered_specialist_ids=tuple(profile.id for profile in profiles),
    )
    try:
        response = _bounded_classification(optional_classifier, request)
    except (TimeoutError, ValueError):
        return _clarification(clean_query, candidates, "Optional classifier was unavailable or timed out")
    selected = next((profile for profile in profiles if profile.id == response.specialist_id), None)
    if type(response.tokens_used) is not int or not 0 <= response.tokens_used <= classifier_token_budget:
        return _clarification(clean_query, candidates, "Optional classifier exceeded its token budget")
    if (
        selected is None or type(response.confidence) not in (int, float)
        or not math.isfinite(response.confidence)
        or not MIN_ROUTE_CONFIDENCE <= response.confidence <= 1.0
    ):
        return _clarification(
            clean_query, candidates, "Optional classifier returned an invalid or low-confidence route"
        )

    classified = RoutingCandidate(
        profile=selected,
        confidence=response.confidence,
        score=response.confidence,
        reasons=("Configured optional classifier selected a registered specialist from redacted features",),
    )
    remaining = [candidate for candidate in candidates if candidate.profile.id != selected.id]
    return _routed(clean_query, classified, [classified, *remaining], registry_path, force_critical)
