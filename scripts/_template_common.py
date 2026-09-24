"""Shared, dependency-free implementation for PARK project generation."""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
from pathlib import Path


TEMPLATE_MARKER = ".portable-agent-template"
SKIP_NAMES = {".git", "LICENSE", "__pycache__", ".DS_Store"}
DISTRIBUTION_IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", ".DS_Store", "*.local.json", "churn-v*.json", "churn-v*.md"
)
LICENSE_CHOICES = ("mit", "apache-2.0", "none")


class TemplateError(RuntimeError):
    """Raised when a generation safety invariant is not met."""


def template_root() -> Path:
    return Path(__file__).resolve().parents[1]


def ensure_empty_destination(destination: Path) -> None:
    if destination.exists() and not destination.is_dir():
        raise TemplateError(f"destination exists and is not a directory: {destination}")
    if destination.exists() and any(destination.iterdir()):
        raise TemplateError(f"destination is not empty; refusing to overwrite: {destination}")


def copy_template(source: Path, destination: Path) -> None:
    source = source.resolve()
    destination = destination.resolve()
    if destination == source or source in destination.parents:
        raise TemplateError("destination cannot be the template or a directory inside it")

    ensure_empty_destination(destination)
    destination.mkdir(parents=True, exist_ok=True)
    excluded = DISTRIBUTION_IGNORE(str(source), [item.name for item in source.iterdir()])
    for item in source.iterdir():
        if item.name in SKIP_NAMES or item.name in excluded:
            continue
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(
                item,
                target,
                ignore=DISTRIBUTION_IGNORE,
            )
        else:
            shutil.copy2(item, target)


def validate_slug(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value):
        raise TemplateError(
            "project slug must contain lowercase letters, digits, and single hyphens"
        )
    return value


def inferred_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        raise TemplateError("could not derive a project slug from the supplied name")
    return validate_slug(slug)


def validate_owner(value: str | None) -> str | None:
    if value is None:
        return None
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", value):
        raise TemplateError("GitHub owner is not a valid user or organization name")
    return value


def replace_tokens(root: Path, replacements: dict[str, str]) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rendered = original
        for token, value in replacements.items():
            rendered = rendered.replace(token, value)
        if rendered != original:
            path.write_text(rendered, encoding="utf-8")


def write_license(root: Path, choice: str, copyright_holder: str) -> None:
    license_path = root / "LICENSE"
    if choice == "none":
        license_path.unlink(missing_ok=True)
        return
    source = template_root() / "templates" / "licenses" / f"{choice}.txt"
    if not source.is_file():
        raise TemplateError(f"license template is missing: {source}")
    text = source.read_text(encoding="utf-8")
    text = text.replace("{{YEAR}}", str(dt.date.today().year))
    text = text.replace("{{COPYRIGHT_HOLDER}}", copyright_holder)
    license_path.write_text(text, encoding="utf-8")


def synchronize_claude_skills(root: Path) -> None:
    canonical = root / ".agents" / "skills"
    target = root / ".claude" / "skills"
    if not canonical.is_dir():
        raise TemplateError(f"canonical skills directory is missing: {canonical}")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    (target / ".park-generated").write_text(
        "Generated from .agents/skills by scripts/agent/sync_adapters.py.\n",
        encoding="utf-8",
    )
    for skill in sorted(canonical.iterdir()):
        if skill.is_dir() and not skill.name.startswith("."):
            shutil.copytree(
                skill,
                target / skill.name,
                ignore=DISTRIBUTION_IGNORE,
            )


def configure_project(
    root: Path,
    *,
    name: str,
    description: str,
    slug: str | None,
    github_owner: str | None,
    license_choice: str,
    copyright_holder: str | None,
    default_branch: str,
) -> None:
    root = root.resolve()
    marker = root / TEMPLATE_MARKER
    if not marker.is_file():
        raise TemplateError(
            f"{root} is not an unconfigured PARK template (missing {TEMPLATE_MARKER})"
        )
    if license_choice not in LICENSE_CHOICES:
        raise TemplateError(f"unsupported license choice: {license_choice}")
    project_slug = validate_slug(slug) if slug else inferred_slug(name)
    owner = validate_owner(github_owner)
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", default_branch):
        raise TemplateError("default branch contains unsupported characters")

    project_readme = root / "templates" / "project" / "README.md"
    if not project_readme.is_file():
        raise TemplateError(f"project README template is missing: {project_readme}")
    (root / "README.md").write_text(project_readme.read_text(encoding="utf-8"), encoding="utf-8")

    repository = f"{owner}/{project_slug}" if owner else project_slug
    replacements = {
        "COPS (Copilot Operations Plugins for Security)": name,
        "copilot-operation-plugin-for-security": project_slug,
        "copilot-operations-plugin-for-security": project_slug,
        "Portable security operations plugins and repository-aware logging guidance for coding assistants.": description,
        "sodejm": owner or "OWNER",
        "sodejm/copilot-operation-plugin-for-security": repository,
        "sodejm/copilot-operations-plugin-for-security": repository,
        "main": default_branch,
    }
    replace_tokens(root, replacements)
    holder = copyright_holder or owner or name
    write_license(root, license_choice, holder)
    # This workflow only works from the source PARK checkout. Generated projects
    # deliberately remove the project generator, so do not leave a broken skill
    # advertising that capability in their canonical skill collection.
    template_creator_skill = root / ".agents" / "skills" / "template-project-creator"
    if template_creator_skill.exists():
        shutil.rmtree(template_creator_skill)
    synchronize_claude_skills(root)
    marker.unlink()
    # Generator assets are needed by PARK itself, not by a configured project.
    # Keep _template_common.py because generated adapter synchronization imports it.
    for generator_file in ("create_project.py", "configure_project.py"):
        (root / "scripts" / generator_file).unlink(missing_ok=True)
    for generator_directory in ("templates", "tests"):
        path = root / generator_directory
        if path.exists():
            shutil.rmtree(path)


def initialize_git(root: Path, default_branch: str) -> None:
    import subprocess

    result = subprocess.run(
        ["git", "init", "-b", default_branch],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise TemplateError(f"git initialization failed: {detail}")


def display_path(path: Path) -> str:
    return os.fspath(path.resolve())
