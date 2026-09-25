"""Build and inspect host-neutral Agent Plugins v1.0.0 packages."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .catalog import load_json
from .mcp_validation import MCPValidationError, validate_mcp_configuration
from .prerequisites import validate_prerequisites
from .validation import ValidationError, _skill_frontmatter, validate_agent_plugin_manifest


# Every new root entry must be deliberately classified before packaging.
PORTABLE_ENTRIES = {
    "plugin.json", "mcp.json", "skills", "scripts", "docs", "examples", "LICENSE", "README.md",
    "CHANGELOG.md", "SECURITY.md", "SOURCE_PROVENANCE.md", "walkthrough.md",
    "hunts", "profiles", "schemas", "fixtures", "evaluations", "huntwb",
    "investigationwb", "com.github.copilot", "com.sodejm.copse",
}
SOURCE_ONLY_ENTRIES = {
    ".claude-plugin", ".codex-plugin", "agents", "commands", "adapters",
    "package.json", ".gitignore", "Makefile", "task.md", "tests",
}
NATIVE_ENTRIES = {".claude-plugin", ".codex-plugin", "agents", "commands", "adapters"}


def _reject_links(path: Path) -> None:
    if path.is_symlink():
        raise ValidationError(f"portable export does not accept symlinks: {path}")
    if path.is_dir():
        for child in path.rglob("*"):
            if child.is_symlink():
                raise ValidationError(f"portable export does not accept symlinks: {child}")


def _tracked_files(source: Path) -> list[Path]:
    """Use the Git index as the reviewed inventory for a portable export."""

    result = subprocess.run(
        ["git", "-C", str(source), "ls-files", "--cached", "-z", "--", "."],
        capture_output=True, check=False,
    )
    if result.returncode:
        raise ValidationError(f"portable export requires a Git checkout: {source}")
    files = [Path(os.fsdecode(item)) for item in result.stdout.split(b"\0") if item]
    if any(path.is_absolute() or ".." in path.parts for path in files):
        raise ValidationError(f"Git returned an unsafe package path for {source}")
    return sorted(files)


def _validate_markdown_links(package: Path) -> None:
    """Keep shipped relative links within the shipped package."""

    for markdown in package.rglob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", markdown.read_text(encoding="utf-8")):
            parsed = urlsplit(target)
            path = unquote(parsed.path)
            if not path or parsed.scheme:
                continue
            linked = (markdown.parent / path).resolve()
            if not linked.is_relative_to(package.resolve()) or not linked.is_file():
                raise ValidationError(f"broken portable documentation link: {markdown}: {target}")


def validate_portable_package(package: Path) -> None:
    """Check the published package's standard root and essential content."""

    entries = {path.name for path in package.iterdir()}
    unexpected = entries - PORTABLE_ENTRIES
    if unexpected:
        raise ValidationError(f"portable package has unreviewed root entries: {sorted(unexpected)}")
    if entries & NATIVE_ENTRIES:
        raise ValidationError("portable package contains native host files")
    for entry in entries:
        _reject_links(package / entry)
    _validate_markdown_links(package)
    manifest = load_json(package / "plugin.json", package)
    validate_agent_plugin_manifest(manifest, f"{package}/plugin.json")
    mcp_path = package / "mcp.json"
    if mcp_path.exists():
        try:
            validate_mcp_configuration(load_json(mcp_path, package), str(mcp_path), package)
        except MCPValidationError as error:
            raise ValidationError(str(error)) from error
    skills = sorted((package / "skills").glob("*/SKILL.md"))
    if not skills:
        raise ValidationError(f"{package} must contain at least one skill")
    for skill in skills:
        _skill_frontmatter(skill, package)
    namespace = "com.sodejm.copse"
    if manifest.get("extensions", {}).get(namespace) is None:
        raise ValidationError(f"{package}/plugin.json must declare {namespace}")
    prereq = package / namespace / "prerequisites.json"
    validate_prerequisites(load_json(prereq, package), str(prereq))


def export_portable_package(source: Path, destination: Path) -> None:
    """Copy approved portable entries to a new directory, then validate it."""

    if destination.exists():
        raise ValidationError(f"portable export destination already exists: {destination}")
    if not source.is_dir():
        raise ValidationError(f"plugin source does not exist: {source}")
    unknown = {entry.name for entry in source.iterdir()} - PORTABLE_ENTRIES - SOURCE_ONLY_ENTRIES
    if unknown:
        raise ValidationError(f"plugin source has unreviewed root entries: {sorted(unknown)}")
    for name in PORTABLE_ENTRIES:
        if (source / name).exists() or (source / name).is_symlink():
            _reject_links(source / name)
    tracked = _tracked_files(source)
    destination.mkdir(parents=True)
    try:
        for relative in tracked:
            if relative.parts[0] not in PORTABLE_ENTRIES:
                continue
            entry = source / relative
            for parent in (source / Path(*relative.parts[:index])
                           for index in range(1, len(relative.parts))):
                if parent.is_symlink():
                    raise ValidationError(f"portable export does not accept symlinks: {parent}")
            _reject_links(entry)
            if not entry.is_file():
                raise ValidationError(f"tracked package file is missing: {entry}")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(entry, target)
        validate_portable_package(destination)
    except Exception:
        shutil.rmtree(destination)
        raise
