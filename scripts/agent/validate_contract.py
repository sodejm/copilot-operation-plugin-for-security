#!/usr/bin/env python3
"""Validate COPS portable repository contract and canonical skills."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from repository_files import repository_files


ROOT = Path(__file__).resolve().parents[2]
REQUIRED = (
    "AGENTS.md",
    "CLAUDE.md",
    ".github/copilot-instructions.md",
    ".agents/skills",
    "docs/COMPATIBILITY.md",
    "docs/SECURITY_MODEL.md",
)
SKILL_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
PRIVATE_PATHS = (
    re.compile("/" + r"Users/[^/\s]+/"),
    re.compile("/" + r"home/[^/\s]+/"),
    re.compile(r"[A-Za-z]:\\" + r"Users\\[^\\\s]+\\"),
)
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^)\s]+)")
MARKDOWN_REFERENCE = re.compile(
    r"^\s{0,3}\[[^\]]+\]:\s*(?P<target><[^>]+>|\S+)"
)


def frontmatter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("missing opening YAML frontmatter delimiter")
    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ValueError("missing closing YAML frontmatter delimiter") from error
    values: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def validate_skills(errors: list[str]) -> None:
    skills = ROOT / ".agents" / "skills"
    if not skills.is_dir():
        return
    for directory in sorted(path for path in skills.iterdir() if path.is_dir()):
        skill = directory / "SKILL.md"
        if not skill.is_file():
            errors.append(f"{directory.relative_to(ROOT)}: missing SKILL.md")
            continue
        try:
            metadata = frontmatter(skill)
        except ValueError as error:
            errors.append(f"{skill.relative_to(ROOT)}: {error}")
            continue
        name = metadata.get("name", "")
        if name != directory.name or not SKILL_NAME.fullmatch(name):
            errors.append(f"{skill.relative_to(ROOT)}: name must match kebab-case directory name")
        if not metadata.get("description"):
            errors.append(f"{skill.relative_to(ROOT)}: description is required")


def validate_portability(errors: list[str]) -> None:
    for path in repository_files(ROOT):
        if ".claude" in path.relative_to(ROOT).parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in PRIVATE_PATHS:
            if pattern.search(text):
                errors.append(f"{path.relative_to(ROOT)}: contains a machine-specific home path")
                break


def validate_markdown_links(errors: list[str]) -> None:
    """Check repository-relative Markdown targets that GitHub will render."""
    for path in repository_files(ROOT):
        if path.suffix != ".md":
            continue
        relative = path.relative_to(ROOT)
        # This source file is rendered at the generated repository root, where
        # its relative targets resolve. The generated repository is separately
        # validated by the test suite.
        if relative == Path("templates/project/README.md"):
            continue
        in_fence = False
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if re.match(r"^\s*(```|~~~)", line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            matches = list(MARKDOWN_LINK.finditer(line))
            reference = MARKDOWN_REFERENCE.match(line)
            if reference:
                matches.append(reference)
            for match in matches:
                target = match.group("target").strip("<>")
                parsed = urlsplit(target)
                if (
                    parsed.scheme
                    or parsed.netloc
                    or target.startswith(("#", "/"))
                    or not parsed.path
                ):
                    continue
                destination = (path.parent / unquote(parsed.path)).resolve()
                if not destination.exists():
                    errors.append(
                        f"{relative}:{line_number}: Markdown target does not exist: {target}"
                    )


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        if not (ROOT / relative).exists():
            errors.append(f"missing required path: {relative}")
    if (ROOT / ".portable-agent-template").is_file():
        generator_paths = (
            "scripts/create_project.py",
            "scripts/configure_project.py",
            "templates/project/README.md",
        )
        for relative in generator_paths:
            if not (ROOT / relative).exists():
                errors.append(f"template repository is missing generator path: {relative}")
    validate_skills(errors)
    validate_portability(errors)
    validate_markdown_links(errors)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Repository contract is valid ({len(list((ROOT / '.agents/skills').glob('*/SKILL.md')))} skills).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
