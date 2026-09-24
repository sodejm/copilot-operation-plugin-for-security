"""Validate the complete distributable package without third-party dependencies."""

from __future__ import annotations

import re
import stat
from typing import Any

from .adapters import EXPECTED_SKILLS, verify_adapters
from .contracts import validate_library
from .errors import ContentError
from .paths import PACKAGE_ROOT, SKILLS_DIR, load_json
from .reports import release_subject


_REQUIRED_DOCS = (
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "SOURCE_PROVENANCE.md",
    "docs/ARCHITECTURE.md",
    "docs/CROSS_PLATFORM.md",
    "docs/OPERATIONS.md",
    "evaluations/EVALUATION_PROTOCOL.md",
)
_SCHEMAS = (
    "curated-fixture.schema.json",
    "external-evidence.schema.json",
    "hunt.schema.json",
    "release-report.schema.json",
    "surface-profile.schema.json",
)
_FRONTMATTER_NAME = re.compile(r"^name:\s*([a-z0-9][a-z0-9-]*)\s*$")


def _validate_skill(path: Any, expected_name: str) -> None:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if len(lines) > 500 or len(lines) < 5 or lines[0] != "---":
        raise ContentError(f"invalid skill length or frontmatter: {path}")
    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ContentError(f"unclosed skill frontmatter: {path}") from error
    fields: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" not in line:
            raise ContentError(f"malformed skill frontmatter: {path}")
        key, value = line.split(":", 1)
        if key in fields:
            raise ContentError(f"duplicate skill frontmatter field: {path}")
        fields[key] = value.strip()
    if set(fields) != {"name", "description"}:
        raise ContentError(f"skill frontmatter must contain name and description only: {path}")
    if not _FRONTMATTER_NAME.fullmatch(f"name: {fields['name']}"):
        raise ContentError(f"invalid skill name: {path}")
    if fields["name"] != expected_name or not fields["description"]:
        raise ContentError(f"skill name or description invalid: {path}")


def validate_package() -> dict[str, Any]:
    """Check contracts, schemas, skill metadata, adapters, and source inventory."""

    contract = validate_library()
    adapters = verify_adapters()
    for relative in _REQUIRED_DOCS:
        path = PACKAGE_ROOT / relative
        if not path.is_file() or path.is_symlink() or not path.read_bytes().strip():
            raise ContentError(f"required package document is missing or empty: {relative}")
    schema_dir = PACKAGE_ROOT / "schemas"
    found = tuple(path.name for path in sorted(schema_dir.glob("*.schema.json")))
    if found != _SCHEMAS:
        raise ContentError(f"schema inventory differs: {found}")
    for name in _SCHEMAS:
        schema = load_json(schema_dir / name)
        if not isinstance(schema, dict) or schema.get("$schema") is None:
            raise ContentError(f"invalid JSON schema document: {name}")
    skill_names = tuple(path.parent.name for path in sorted(SKILLS_DIR.glob("*/SKILL.md")))
    if skill_names != EXPECTED_SKILLS:
        raise ContentError(f"canonical skill inventory differs: {skill_names}")
    for name in skill_names:
        _validate_skill(SKILLS_DIR / name / "SKILL.md", name)

    subject = release_subject()
    for relative in subject["artifacts"]:
        path = PACKAGE_ROOT / relative
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ContentError(f"release input is not a regular file: {relative}")
    return {
        "status": "passed",
        "package": "sentinel-hunt-workbench",
        "contract": contract,
        "adapters": adapters,
        "schema_count": len(_SCHEMAS),
        "skill_count": len(skill_names),
        "release_subject_sha256": subject["sha256"],
        "release_input_count": subject["artifact_count"],
        "assurance": "offline_package_validation_only",
    }
