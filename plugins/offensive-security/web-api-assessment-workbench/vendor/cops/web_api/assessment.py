"""Evidence-based object-authorization and request-rate assessment."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any

from .models import ReplayResponse


class AssessmentVerdict(str, Enum):
    """Conclusion supported by the collected response evidence."""

    PASS = "pass"
    FAIL = "fail"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass(frozen=True)
class AuthorizationCase:
    """One identity's observed access to an object through one API surface."""

    request_id: str
    surface: str
    actor: str
    object_id: str
    expected_allowed: bool
    response: ReplayResponse

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "surface": self.surface,
            "actor": self.actor,
            "object_id": self.object_id,
            "expected_allowed": self.expected_allowed,
            "response": self.response.to_dict(),
        }


@dataclass(frozen=True)
class AuthorizationAssessment:
    """Assessment of owner, cross-user, and anonymous object access."""

    verdict: AssessmentVerdict
    cases: tuple[AuthorizationCase, ...]
    findings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cops.web-api-authorization-assessment/v1",
            "verdict": self.verdict.value,
            "cases": [case.to_dict() for case in self.cases],
            "findings": list(self.findings),
        }


@dataclass(frozen=True)
class RateLimitAssessment:
    """Assessment of observed throttling behavior for one bounded identity."""

    verdict: AssessmentVerdict
    status_codes: tuple[int, ...]
    retry_after_observed: bool
    evidence_count: int
    minimum_attempts: int
    findings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cops.web-api-rate-limit-assessment/v1",
            "verdict": self.verdict.value,
            "status_codes": list(self.status_codes),
            "retry_after_observed": self.retry_after_observed,
            "evidence_count": self.evidence_count,
            "minimum_attempts": self.minimum_attempts,
            "findings": list(self.findings),
        }


def _graphql_access_allowed(response: ReplayResponse) -> bool | None:
    if response.status_code == 0:
        return None
    if response.status_code in {401, 403}:
        return False
    if not (200 <= response.status_code < 300):
        return None
    try:
        document = json.loads(response.body_excerpt)
    except (json.JSONDecodeError, TypeError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    data = document.get("data")
    if isinstance(data, dict) and data.get("object") is not None:
        return True
    errors = document.get("errors")
    if isinstance(data, dict) and "object" in data and isinstance(errors, list) and errors:
        codes = [error.get("extensions", {}).get("code") for error in errors
                 if isinstance(error, dict) and isinstance(error.get("extensions"), dict)]
        if len(codes) == len(errors) and all(code in {"UNAUTHENTICATED", "FORBIDDEN"} for code in codes):
            return False
    return None


def _access_allowed(case: AuthorizationCase) -> bool | None:
    if case.surface == "graphql":
        return _graphql_access_allowed(case.response)
    if case.surface != "rest" or case.response.status_code == 0:
        return None
    if case.response.status_code in {401, 403, 404}:
        return False
    if 200 <= case.response.status_code < 300:
        return True
    return None


def assess_object_authorization(cases: list[AuthorizationCase]) -> AuthorizationAssessment:
    """Compare observed access against owner/other-user/anonymous expectations."""
    findings: list[str] = []
    required = {(surface, actor) for surface in ("rest", "graphql") for actor in ("owner", "other", "anonymous")}
    observed = {(case.surface, case.actor) for case in cases}
    missing = sorted(required - observed)
    if missing:
        findings.append("Missing required cases: " + ", ".join(f"{surface}/{actor}" for surface, actor in missing))

    mismatches = False
    indeterminate = bool(missing)
    identities: set[tuple[str, str]] = set()
    request_ids: set[str] = set()
    object_ids = {case.object_id for case in cases}
    if len(object_ids) != 1 or not all(object_ids):
        indeterminate = True
        findings.append("Cases must compare access to the same nonempty object")
    for case in cases:
        identity = (case.surface, case.actor)
        if (identity in identities or case.request_id in request_ids or identity not in required
                or case.response.request_id != case.request_id or case.expected_allowed != (case.actor == "owner")
                or not case.response.replay_success or case.response.error_message):
            indeterminate = True
            findings.append(f"{case.request_id}: inconsistent or duplicate authorization evidence")
            continue
        identities.add(identity)
        request_ids.add(case.request_id)
        allowed = _access_allowed(case)
        if allowed is None:
            indeterminate = True
            findings.append(f"{case.request_id}: response does not establish an authorization outcome")
        elif allowed != case.expected_allowed:
            mismatches = True
            findings.append(
                f"{case.request_id}: {case.surface} {case.actor} access was "
                f"{'allowed' if allowed else 'denied'}, expected {'allowed' if case.expected_allowed else 'denied'}"
            )

    if mismatches:
        verdict = AssessmentVerdict.FAIL
    elif indeterminate:
        verdict = AssessmentVerdict.INSUFFICIENT_EVIDENCE
    else:
        verdict = AssessmentVerdict.PASS
    return AuthorizationAssessment(verdict, tuple(cases), tuple(findings))


def assess_rate_limit(
    responses: list[ReplayResponse], *, minimum_attempts: int = 3
) -> RateLimitAssessment:
    """Require enough attempts and an explicit 429 with retry guidance for a pass."""
    if minimum_attempts < 2:
        raise ValueError("minimum_attempts must be at least 2")
    statuses = tuple(response.status_code for response in responses)
    retry_after = any(
        response.status_code == 429
        and any(key.lower() == "retry-after" and bool(value) for key, value in response.headers.items())
        for response in responses
    )
    if len(responses) < minimum_attempts:
        verdict = AssessmentVerdict.INSUFFICIENT_EVIDENCE
        findings = (f"Observed {len(responses)} requests; at least {minimum_attempts} are required",)
    elif len({response.request_id for response in responses}) != len(responses):
        verdict = AssessmentVerdict.INSUFFICIENT_EVIDENCE
        findings = ("Repeated request evidence cannot establish independent throttling attempts",)
    elif any(status == 0 or status >= 500 for status in statuses) or any(
        not response.replay_success or response.error_message for response in responses
    ):
        verdict = AssessmentVerdict.INSUFFICIENT_EVIDENCE
        findings = ("Transport or server failures prevent a rate-limit conclusion",)
    elif 429 in statuses and retry_after:
        verdict = AssessmentVerdict.PASS
        findings = ()
    elif 429 in statuses:
        verdict = AssessmentVerdict.INSUFFICIENT_EVIDENCE
        findings = ("HTTP 429 was observed without Retry-After guidance",)
    elif all(200 <= status < 300 for status in statuses):
        verdict = AssessmentVerdict.FAIL
        findings = ("All bounded attempts succeeded without rate-limit enforcement",)
    else:
        verdict = AssessmentVerdict.INSUFFICIENT_EVIDENCE
        findings = ("Observed statuses do not establish request-rate enforcement",)
    return RateLimitAssessment(verdict, statuses, retry_after, len(responses), minimum_attempts, findings)
