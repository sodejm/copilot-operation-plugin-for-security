"""Deterministic target selection for ordinary-language engagement goals."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from cops.contracts.models import Engagement
from cops.evidence.canonical import EvidenceError, digest, timestamp

from .errors import GoalResolutionError
from .intake import validate_engagement_intake

RESULT_VERSION = "cops.engagement-goal-result/v1"
MAX_GOAL_CHARS = 4096
MAX_SCOPE_TARGETS = 1024
_TARGET_LEFT_BOUNDARY = r"A-Za-z0-9_.:/-"
_TARGET_RIGHT_BOUNDARY = r"A-Za-z0-9_:/-"
_ILLUSTRATIVE = re.compile(
    r"(?<![A-Za-z0-9_])(?:for\s+example|for\s+instance|e\.g\.|such\s+as|example\s+target)(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_DIRECT_ASSESSMENT = re.compile(
    r"\A\s*(?:(?:please|can\s+you|could\s+you|would\s+you|help\s+me(?:\s+to)?|"
    r"i\s+(?:want|need)\s+(?:you\s+)?to|i(?:'d|\s+would)\s+like\s+(?:you\s+)?to)\s+)?"
    r"(?P<verb>assess|scan|inspect|test|enumerate|discover|evaluate|probe|check)\b",
    re.IGNORECASE,
)
_NEGATED_ASSESSMENT = re.compile(
    r"\b(?:do\s+not|don['’]t|never|avoid|stop)\b.{0,60}?"
    r"\b(?:assess|scan|inspect|test|enumerate|discover|evaluate|run|perform|start|execute|probe|check)\b",
    re.IGNORECASE,
)


def _fail(message: str, *, code: str, next_action: str) -> GoalResolutionError:
    return GoalResolutionError(message, code=code, next_action=next_action)


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for opener, closer in (('"', '"'), ("'", "'"), ("`", "`"), ("“", "”"), ("‘", "’")):

        def find_quote(character: str, offset: int) -> int:
            while (position := text.find(character, offset)) >= 0:
                if character != "'" or not (
                    position > 0
                    and position + 1 < len(text)
                    and text[position - 1].isalnum()
                    and text[position + 1].isalnum()
                ):
                    return position
                offset = position + 1
            return -1

        start = 0
        while True:
            left = find_quote(opener, start)
            if left < 0:
                break
            right = find_quote(closer, left + len(opener))
            if right < 0:
                spans.append((left, len(text)))
                break
            spans.append((left, right + len(closer)))
            start = right + len(closer)
    return spans


def _illustrative_spans(text: str) -> list[tuple[int, int]]:
    # A sentence boundary cannot be inferred safely from hostnames or IP
    # addresses. Keep the rest of the request non-authoritative after an
    # illustrative marker and ask for a separate, direct request instead.
    return [(match.start(), len(text)) for match in _ILLUSTRATIVE.finditer(text)]


def _target_occurrences(text: str, target: str) -> list[tuple[int, int]]:
    pattern = re.compile(
        rf"(?<![{_TARGET_LEFT_BOUNDARY}]){re.escape(target)}"
        rf"(?![{_TARGET_RIGHT_BOUNDARY}]|\.[A-Za-z0-9_-])",
        re.IGNORECASE,
    )
    return [(match.start(), match.end()) for match in pattern.finditer(text)]


def _inside(span: tuple[int, int], containers: list[tuple[int, int]]) -> bool:
    return any(start <= span[0] and span[1] <= end for start, end in containers)


def _reject_overlapping_exclusions(target: str, excluded: list[str]) -> None:
    """Do not select a network that could later include an excluded address."""
    try:
        target_network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return
    for exclusion in excluded:
        try:
            excluded_network = ipaddress.ip_network(exclusion, strict=False)
        except ValueError:
            continue
        if target_network.version == excluded_network.version and target_network.overlaps(excluded_network):
            raise _fail(
                "Selected target overlaps an excluded address or network",
                code="overlapping_exclusion",
                next_action=(
                    "Select an included target that does not overlap any exclusion, "
                    "or split the scope into separate non-overlapping targets."
                ),
            )


def _resolve_target(goal: str, engagement: dict[str, Any], selection: dict[str, Any]) -> tuple[str, str]:
    included = [str(target).strip() for target in engagement["scope"]["included_targets"]]
    excluded = [str(target).strip() for target in engagement["scope"].get("excluded_targets", [])]
    non_authoritative = [*_quoted_spans(goal), *_illustrative_spans(goal)]

    referenced_exclusions = [target for target in excluded if _target_occurrences(goal, target)]
    if referenced_exclusions:
        raise _fail(
            f"Goal references excluded target(s): {', '.join(referenced_exclusions)}",
            code="excluded_target",
            next_action="Remove excluded targets and name exactly one included target.",
        )

    explicit: list[str] = []
    non_authoritative_targets: list[str] = []
    for target in included:
        occurrences = _target_occurrences(goal, target)
        if any(_inside(occurrence, non_authoritative) for occurrence in occurrences):
            non_authoritative_targets.append(target)
        if any(not _inside(occurrence, non_authoritative) for occurrence in occurrences):
            explicit.append(target)

    if non_authoritative_targets:
        raise _fail(
            "Quoted or illustrative target text cannot select engagement scope: "
            + ", ".join(non_authoritative_targets),
            code="non_authoritative_target",
            next_action="Name exactly one included target as a direct instruction, outside quotations and examples.",
        )
    if len(explicit) > 1:
        raise _fail(
            "This resolver accepts exactly one target; the goal names multiple included targets: "
            + ", ".join(explicit),
            code="ambiguous_targets",
            next_action="Submit one goal per exact included target.",
        )

    selected_target = selection.get("target")
    if selected_target is not None and not isinstance(selected_target, str):
        raise _fail(
            "metadata.goal_selection.target must be a string",
            code="invalid_selection",
            next_action="Record one exact included target in metadata.goal_selection.target.",
        )
    canonical_selection = (
        next(
            (target for target in included if target.casefold() == selected_target.strip().casefold()),
            None,
        )
        if selected_target is not None
        else None
    )
    if selected_target is not None and canonical_selection is None:
        raise _fail(
            "metadata.goal_selection.target is not an exact included target",
            code="selection_out_of_scope",
            next_action="Change metadata.goal_selection.target to an exact member of scope.included_targets.",
        )

    if explicit:
        if canonical_selection is not None and canonical_selection.casefold() != explicit[0].casefold():
            raise _fail(
                "The explicitly named target conflicts with metadata.goal_selection.target",
                code="conflicting_target_selection",
                next_action="Make the direct goal target and recorded engagement selection identical.",
            )
        _reject_overlapping_exclusions(explicit[0], excluded)
        return explicit[0], "goal"
    if canonical_selection is not None:
        _reject_overlapping_exclusions(canonical_selection, excluded)
        return canonical_selection, "engagement_selection"
    raise _fail(
        "Goal does not directly name an included target and the engagement has no recorded target selection",
        code="missing_target_selection",
        next_action="Name exactly one included target directly or set metadata.goal_selection.target.",
    )


def _validate_goal_detail(goal: str, target: str, target_source: str) -> dict[str, Any]:
    """Reject text this bounded resolver cannot faithfully interpret."""
    intent = _DIRECT_ASSESSMENT.match(goal)
    if intent is None:
        raise _fail(
            "Goal is not a direct request for an assessment action",
            code="missing_assessment_intent",
            next_action="Start with a direct request such as 'Assess the selected endpoint'.",
        )
    subject = re.escape(target) if target_source == "goal" else r"the\s+selected(?:\s+production)?\s+endpoint"
    supported_detail = rf"{subject}(?:\s+for\s+exposed\s+services)?(?:\s+safely)?[.!]?"
    detail = goal[intent.end() :].strip()
    if re.fullmatch(supported_detail, detail, re.IGNORECASE) is None:
        raise _fail(
            "Goal contains a target or instruction this resolver cannot interpret",
            code="unsupported_goal_detail",
            next_action=(
                "Use one direct request such as 'Assess the selected endpoint safely.' "
                "Record the assessment limits in the reviewed engagement contract."
            ),
        )
    return {
        "verb": intent.group("verb").lower(),
        "detail": (
            "exposed_services" if re.search(r"\bfor\s+exposed\s+services\b", detail, re.IGNORECASE) else "unspecified"
        ),
        "safe_mode_requested": bool(re.search(r"\bsafely\b", detail, re.IGNORECASE)),
        "status": "unbound",
    }


def resolve_engagement_goal(
    *,
    goal: str,
    engagement: Engagement | dict[str, Any],
) -> dict[str, Any]:
    """Resolve one ordinary-language goal without producing an executable plan."""
    if not isinstance(goal, str) or not goal.strip():
        raise _fail(
            "Goal must be non-empty ordinary-language text",
            code="missing_goal",
            next_action="Provide a direct goal that names exactly one included target.",
        )
    if len(goal) > MAX_GOAL_CHARS:
        raise _fail(
            "Goal exceeds the supported length",
            code="goal_too_long",
            next_action="Provide one direct assessment request of at most 4096 characters.",
        )
    if _NEGATED_ASSESSMENT.search(goal):
        raise _fail(
            "Goal contains an instruction not to perform an assessment action",
            code="negated_assessment",
            next_action="State the assessment you want as a positive instruction, with explicit limits in the engagement contract.",
        )
    if not _DIRECT_ASSESSMENT.search(goal):
        raise _fail(
            "Goal is not a direct request for an assessment action",
            code="missing_assessment_intent",
            next_action="Start with a direct request such as 'Assess the selected endpoint'.",
        )
    raw_engagement = engagement.to_dict() if isinstance(engagement, Engagement) else engagement
    if not isinstance(raw_engagement, dict):
        raise _fail(
            "Engagement must be a contract object",
            code="invalid_engagement",
            next_action="Supply a valid cops.engagement/v1 JSON contract.",
        )
    validated = validate_engagement_intake(dict(raw_engagement))
    scope = validated["scope"]
    if len(scope["included_targets"]) + len(scope.get("excluded_targets", [])) > MAX_SCOPE_TARGETS:
        raise _fail(
            "Engagement contains too many scope targets for goal selection",
            code="scope_too_large",
            next_action="Provide an engagement with at most 1024 included and excluded target entries in total.",
        )
    lifecycle_status = validated["status"]
    if lifecycle_status not in {"planned", "active"}:
        raise _fail(
            "Engagement is no longer in a selectable lifecycle state",
            code="engagement_inactive",
            next_action="Supply a current planned or active engagement and request selection again.",
        )
    now = datetime.now(UTC)
    window = validated["window"]
    if timestamp(window["authorized_until_utc"]) <= now:
        raise _fail(
            "Engagement authorization window has expired",
            code="engagement_window_expired",
            next_action="Refresh and review the engagement window before requesting goal selection.",
        )
    window_status = "upcoming" if timestamp(window["started_at"]) > now else "open"
    metadata = validated.get("metadata", {})
    selection = metadata.get("goal_selection", {}) if isinstance(metadata, dict) else {}
    if not isinstance(selection, dict):
        raise _fail(
            "metadata.goal_selection must be an object",
            code="invalid_selection",
            next_action="Record one exact included target in metadata.goal_selection.target.",
        )

    target, target_source = _resolve_target(goal.strip(), validated, selection)
    requested_intent = _validate_goal_detail(goal.strip(), target, target_source)

    try:
        contract_digest = "sha256:" + digest(validated)
    except EvidenceError as err:
        raise _fail(
            "Engagement exceeds the supported canonical size or structure",
            code="engagement_too_large",
            next_action="Supply a bounded cops.engagement/v1 contract and retry selection.",
        ) from err

    return {
        "result_version": RESULT_VERSION,
        "status": "needs_execution_path",
        "resolution": {
            "target_source": target_source,
            "targets": [target],
            "requested_intent": requested_intent,
            "engagement_binding": {
                "engagement_id": validated["engagement_id"],
                "contract_digest": contract_digest,
                "lifecycle_status": lifecycle_status,
                "window_status": window_status,
                "selection_review_status": "unverified",
            },
        },
        "execution_readiness": {
            "status": "unavailable",
            "reason": (
                "Engagement review, allowed-action mapping, worker adapter, authorization "
                "receipt, and resumable checkpoint are not verified or bound to this request."
            ),
        },
        "coverage": {
            "status": "not_assessed",
            "assessed_targets": [],
            "not_assessed_targets": [target],
            "reason": ("Target selection only: no plan, approval, worker dispatch, or assessment occurred."),
        },
        "next_action": {
            "type": "bind_execution_path",
            "instruction": (
                "Verify engagement provenance and current scope, map the requested intent to "
                "an allowed action, bind a verified worker operation to the target, then "
                "present a bounded executable plan for approval."
            ),
        },
    }
