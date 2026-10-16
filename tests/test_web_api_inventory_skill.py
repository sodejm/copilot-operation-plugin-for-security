from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTOR_SKILL = REPOSITORY_ROOT / ".agents" / "skills" / "web-api-inventory-and-replay" / "SKILL.md"
PACKAGED_SKILL = (
    REPOSITORY_ROOT
    / "plugins"
    / "offensive-security"
    / "attack-surface-planner"
    / "skills"
    / "web-api-inventory-and-replay"
    / "SKILL.md"
)


def test_contributor_and_packaged_scanner_skills_have_identical_contracts():
    assert CONTRIBUTOR_SKILL.read_bytes() == PACKAGED_SKILL.read_bytes()


def test_scanner_skill_requires_sanitized_request_evidence():
    content = CONTRIBUTOR_SKILL.read_text(encoding="utf-8")

    required_safety_terms = (
        "Preserve only a sanitized request summary",
        "query parameter names with every value replaced by `[REDACTED]`",
        "Never retain raw `Authorization`, `Proxy-Authorization`, `Cookie`, or `Set-Cookie` headers",
        "API keys, tokens, query values, or request bodies",
        "digest of approved non-secret content",
    )
    for term in required_safety_terms:
        assert term in content

    assert "Preserve the observed request" not in content
