"""Positive intent for the two-suite Detection Quality review."""

import re
from dataclasses import replace
from pathlib import Path

from .classifier import route_request
from .models import RoutingDecision
from .triad import assemble_triad_plan

SPECIALIST = "cops-detection-engineer"
WORKBENCH = "detection-quality-workbench"
SKILL = "detection-quality-review"

# Match a whole request so an advisory mention, negation or additional action
# cannot become permission to start a different job.
_BUNDLE = r"(?:bundled|packaged|built-in|included)"
_FIXTURES = r"(?:(?:labeled|labelled|synthetic) )?fixture(?:s| (?:sets|suites))"
_KQL = r"(?:microsoft sentinel|sentinel|kql)"
_SPL = r"(?:splunk|spl)"
_BOTH = rf"(?:{_KQL} (?:and|&) {_SPL}|{_SPL} (?:and|&) {_KQL})"
_QUALITY = r"detection[ -]quality(?:[ -](?:workbench|pilot|review))?"
_RULES = rf"(?:the )?(?:{_BUNDLE} )?(?:{_BOTH})(?: detection)? rules"
_SUITES = rf"(?:both|all|the (?:two|bundled|packaged)) (?:{_BUNDLE} )?{_QUALITY} {_FIXTURES}"
_WORKBENCH = rf"(?:the )?{_QUALITY} (?:on|against|with|using) (?:both|all|the bundled) (?:{_BUNDLE} )?{_FIXTURES}"
_AFTER = rf"(?:both|the two) (?:{_BUNDLE} )?{_FIXTURES} (?:for|in|from) (?:the )?{_QUALITY}"
_PLATFORMS = rf"(?:both |the |both the )?(?:{_BUNDLE} )?{_BOTH} {_FIXTURES}"
_CATCH = (
    rf"(?:whether|if) (?:our |the )?{_BOTH} detections (?:catch|cover|detect) (?:the )?{_BUNDLE} (?:cases|fixtures)"
)
_REPORT = (
    r"(?:,? (?:and then|and|then) (?:(?:report|explain|summarize|list|show|identify) "
    r"(?:the |any )?(?:coverage |telemetry )?gaps|tell me what(?:'s| is) missing))?"
)
_INTENT = re.compile(
    rf"(?:please )?(?:(?:can|could|would) you (?:please )?)?"
    rf"(?:check|test|evaluate|review|run|validate|compare) "
    rf"(?:{_RULES} (?:against|on|using|with) (?:their |the |both )?(?:{_BUNDLE} )?{_FIXTURES}"
    rf"|{_CATCH}|{_SUITES}|{_WORKBENCH}|{_AFTER}|{_PLATFORMS}|(?:the )?detection[ -]quality pilot){_REPORT}[.!?]?",
    re.ASCII | re.IGNORECASE,
)


def matches_bundled_review(query: str) -> bool:
    """Recognize a complete offline request. An identifier alone is advisory."""
    return len(query) <= 600 and _INTENT.fullmatch(" ".join(query.split())) is not None


def route_bundled_review(
    query: str, *, registry_path: Path | None = None, force_critical: bool = False
) -> RoutingDecision | None:
    """Return the registered selection for a complete request for the two suites."""
    if matches_bundled_review(query):
        # A complete request for this fixed operation has a declared owner.
        # Ask the registry router for that exact profile, retaining its constraints.
        owner = route_request(SPECIALIST, registry_path=registry_path)
        profile = owner.primary_profile
        if owner.status == "routed" and profile and profile.primary_plugin == WORKBENCH and SKILL in profile.skills:
            reasons = ("Explicit request for both bundled Detection Quality fixture suites",)
            candidate = replace(owner.ranked_candidates[0], reasons=reasons)
            critical = force_critical or profile.is_critical
            return replace(
                owner,
                query=query,
                recommended_skills=(SKILL,),
                match_reasons=reasons,
                ranked_candidates=(candidate,),
                criticality="critical" if critical else "normal",
                triad_plan=assemble_triad_plan(profile, query, registry_path) if critical else None,
            )
    return None
