"""Build and inspect host-neutral Agent Plugins v1.0.0 packages."""

from __future__ import annotations

import shutil
from pathlib import Path

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
    destination.mkdir(parents=True)
    try:
        for entry in sorted(source.iterdir()):
            if entry.name not in PORTABLE_ENTRIES:
                continue
            _reject_links(entry)
            target = destination / entry.name
            if entry.is_dir():
                shutil.copytree(entry, target)
            elif entry.is_file():
                shutil.copy2(entry, target)
            else:
                raise ValidationError(f"unsupported package entry: {entry}")
        validate_portable_package(destination)
    except Exception:
        shutil.rmtree(destination)
        raise
