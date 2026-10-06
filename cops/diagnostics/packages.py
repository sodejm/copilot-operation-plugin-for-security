"""Package workflow and structure diagnostics for COPS plugins."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import DiagnosticCheck, PackageDiagnostic


def diagnose_plugin_package(package_dir: Path) -> PackageDiagnostic:
    """Inspect and diagnose a single plugin package directory."""
    package_id = package_dir.name
    category = package_dir.parent.name
    checks: list[DiagnosticCheck] = []

    # 1. Check plugin.json manifest
    manifest_path = package_dir / "plugin.json"
    manifest_valid = False
    if manifest_path.is_file():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            required_keys = {"name", "version", "description"}
            if required_keys <= data.keys():
                manifest_valid = True
                checks.append(DiagnosticCheck("manifest", "passed", f"Valid manifest for {package_id}"))
            else:
                missing = sorted(required_keys - data.keys())
                checks.append(DiagnosticCheck("manifest", "failed", f"Manifest missing required keys: {missing}"))
        except (json.JSONDecodeError, OSError) as err:
            checks.append(DiagnosticCheck("manifest", "failed", f"Failed to parse manifest: {err}"))
    else:
        checks.append(DiagnosticCheck("manifest", "failed", "Missing plugin.json manifest"))

    # 2. Check README.md
    readme_path = package_dir / "README.md"
    if readme_path.is_file() and len(readme_path.read_text(encoding="utf-8").strip()) > 50:
        checks.append(DiagnosticCheck("readme", "passed", "README.md present with adequate documentation"))
    else:
        checks.append(DiagnosticCheck("readme", "warning", "README.md missing or contains minimal content"))

    # 3. Check docs/PLAYBOOK.md
    playbook_path = package_dir / "docs" / "PLAYBOOK.md"
    has_playbook = playbook_path.is_file() and len(playbook_path.read_text(encoding="utf-8").strip()) > 50
    if has_playbook:
        checks.append(DiagnosticCheck("playbook", "passed", "Operational playbook present in docs/PLAYBOOK.md"))
    else:
        checks.append(DiagnosticCheck("playbook", "warning", "docs/PLAYBOOK.md missing or minimal"))

    # 4. Check scripts/validate-package.py
    script_path = package_dir / "scripts" / "validate-package.py"
    has_validation_script = script_path.is_file()
    if has_validation_script:
        checks.append(DiagnosticCheck("validation_script", "passed", "Offline package validator present"))
    else:
        checks.append(DiagnosticCheck("validation_script", "warning", "Offline package validator missing"))

    # 5. Check skills/ directory
    skills_dir = package_dir / "skills"
    skills_count = 0
    if skills_dir.is_dir():
        for skill_path in sorted(skills_dir.iterdir()):
            if skill_path.is_dir() and (skill_path / "SKILL.md").is_file():
                skill_content = (skill_path / "SKILL.md").read_text(encoding="utf-8")
                # Basic frontmatter validation
                if skill_content.startswith("---") and "name:" in skill_content and "description:" in skill_content:
                    skills_count += 1
                else:
                    checks.append(DiagnosticCheck(
                        f"skill_{skill_path.name}", "warning",
                        f"Skill {skill_path.name}/SKILL.md missing valid YAML frontmatter"
                    ))
        checks.append(DiagnosticCheck("skills", "passed", f"Found {skills_count} valid skill(s)"))
    else:
        checks.append(DiagnosticCheck("skills", "warning", "No skills directory found"))

    # Determine status
    if not manifest_valid:
        status = "unready"
    elif not has_validation_script or not has_playbook:
        status = "degraded"
    else:
        status = "ready"

    return PackageDiagnostic(
        package_id=package_id,
        category=category,
        status=status,
        manifest_valid=manifest_valid,
        skills_count=skills_count,
        has_playbook=has_playbook,
        has_validation_script=has_validation_script,
        checks=checks,
    )


def diagnose_packages(plugins_root: Path) -> list[PackageDiagnostic]:
    """Inspect and diagnose all packages under plugins/."""
    results: list[PackageDiagnostic] = []
    if not plugins_root.is_dir():
        return results

    for category_dir in sorted(plugins_root.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("."):
            continue
        for package_dir in sorted(category_dir.iterdir()):
            if package_dir.is_dir() and not package_dir.name.startswith("."):
                results.append(diagnose_plugin_package(package_dir))

    return results
