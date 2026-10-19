from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTOR_SKILL = REPOSITORY_ROOT / ".agents" / "skills" / "web-api-inventory-and-replay" / "SKILL.md"
PACKAGED_SKILL = (
    REPOSITORY_ROOT
    / "plugins"
    / "offensive-security"
    / "web-api-assessment-workbench"
    / "skills"
    / "web-api-inventory-and-replay"
    / "SKILL.md"
)
PACKAGE_README = REPOSITORY_ROOT / "plugins" / "offensive-security" / "web-api-assessment-workbench" / "README.md"


def test_contributor_and_packaged_scanner_skills_have_identical_contracts():
    def service_contract(path: Path) -> str:
        return path.read_text(encoding="utf-8").split("## Observed service routing\n", 1)[1].split("\n## ", 1)[0]

    assert service_contract(CONTRIBUTOR_SKILL) == service_contract(PACKAGED_SKILL)


def test_scanner_skill_requires_sanitized_request_evidence():
    required_safety_terms = (
        "Preserve only a sanitized request summary",
        "query parameter names with every value replaced by `[REDACTED]`",
        "Never retain raw `Authorization`, `Proxy-Authorization`, `Cookie`, or `Set-Cookie` headers",
        "API keys, tokens, query values, or request bodies",
        "digest of approved non-secret content",
    )
    for path in (CONTRIBUTOR_SKILL, PACKAGED_SKILL):
        content = path.read_text(encoding="utf-8")
        for term in required_safety_terms:
            assert term in content
        assert "Preserve the observed request" not in content


def test_package_documents_bounded_multi_source_import_and_har_authentication():
    content = PACKAGE_README.read_text(encoding="utf-8")
    for term in (
        "8 MiB input ceiling",
        "provenance_sources",
        "Authorization: Bearer <placeholder>",
        "Authorization: Basic <placeholder>",
        "COPS_WEB_API_BEARER_TOKEN",
        "COPS_WEB_API_BASIC_CREDENTIALS_B64",
    ):
        assert term in content
