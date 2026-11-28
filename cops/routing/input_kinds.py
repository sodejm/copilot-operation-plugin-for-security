"""Offline defensive evidence categories used to clarify ambiguous requests."""

from __future__ import annotations

import re

# Map operator vocabulary to registry IDs. Descriptions help users redact and
# describe an artifact without pasting its contents into the request.
_INPUT_GUIDANCE = {
    "source-diff": (
        "cops-appsec-engineer",
        ("pull request diff", "pr diff", "source diff", "code diff"),
        "A redacted code diff and a description of the behavior that changed.",
    ),
    "alert": (
        "cops-soc-analyst",
        ("siem alert", "alert export", "sign in alert", "login alert"),
        "A redacted alert summary, its time window, and what triggered it.",
    ),
    "incident-timeline": (
        "cops-incident-responder",
        ("incident timeline",),
        "A redacted timeline, known impact, and any containment already performed.",
    ),
    "detection-rule": (
        "cops-detection-engineer",
        ("detection rule", "sigma rule", "yara rule"),
        "A redacted rule, its data source, and the behavior it should detect.",
    ),
    "sentinel-query": (
        "cops-sentinel-kql-engineer",
        ("sentinel kql query", "kql query", "sentinel query"),
        "The redacted query, expected result, and any relevant table names.",
    ),
    "policy-document": (
        "cops-compliance-auditor",
        ("policy document", "control matrix"),
        "The relevant policy excerpt or control IDs and the intended audit outcome.",
    ),
}

INPUT_KINDS = tuple(_INPUT_GUIDANCE)


_KIND_BY_PHRASE = {
    phrase: kind for kind, (_, phrases, _) in _INPUT_GUIDANCE.items() for phrase in phrases
}
_EVIDENCE_PHRASE = re.compile(r"\b(?:" + "|".join(map(re.escape, _KIND_BY_PHRASE)) + r")\b")
_GENERIC_REQUEST_WORDS = frozenset(
    "a an and at can check could examine for have help i inspect look me my our please "
    "some take the these this with would you".split()
)


def describe_evidence(query: str) -> tuple[tuple[str, ...], bool]:
    """Find evidence phrases and identify requests that leave the outcome open."""
    normalized = " ".join(re.findall(r"[a-z0-9]+", query.lower()))
    phrases = _EVIDENCE_PHRASE.findall(normalized)
    kinds = tuple(dict.fromkeys(_KIND_BY_PHRASE[phrase] for phrase in phrases))
    remaining = set(_EVIDENCE_PHRASE.sub(" ", normalized).split())
    return kinds, bool(kinds) and remaining <= _GENERIC_REQUEST_WORDS


def input_guidance(kinds: tuple[str, ...]) -> dict[str, str]:
    """Return matched specialist IDs and the evidence they can use."""
    if any(kind not in _INPUT_GUIDANCE for kind in kinds):
        raise ValueError("Choose one of the supported routing input kinds.")
    return {_INPUT_GUIDANCE[kind][0]: _INPUT_GUIDANCE[kind][2] for kind in kinds}
