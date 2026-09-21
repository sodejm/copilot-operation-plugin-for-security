#!/usr/bin/env python3
"""Validate the Security Logging Advisor package from a repository root."""
from __future__ import annotations
import json
from pathlib import Path
import re

PACKAGE = Path("plugins/logging-telemetry/security-logging-advisor")
REQUIRED_FILES = [
    PACKAGE / "plugin.json",
    PACKAGE / ".codex-plugin/plugin.json",
    PACKAGE / ".claude-plugin/plugin.json",
    PACKAGE / "agents/security-logging-advisor.agent.md",
    PACKAGE / "commands/security-logging-advisor.md",
    PACKAGE / "com.github.copilot/agents/security-logging-advisor.agent.md",
    PACKAGE / "com.github.copilot/commands/security-logging-advisor.md",
    PACKAGE / "skills/repository-context/scripts/collect-repository-context.py",
    PACKAGE / "docs/INSTALL.md", PACKAGE / "docs/ENTERPRISE_ROLLOUT.md",
    PACKAGE / "docs/SECURITY_PRIVACY.md", PACKAGE / "docs/TROUBLESHOOTING.md",
    PACKAGE / "docs/MAINTAINERS.md", PACKAGE / "CHANGELOG.md",
]

def read_json(path: Path, errors: list[str]) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"Failed to parse {path} as JSON: {error}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{path} must contain a JSON object.")
        return {}
    return value

def check_skill(path: Path) -> list[str]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        return [f"Error reading skill file {path}: {error}"]
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", content, re.DOTALL)
    if not match:
        return [f"Skill file {path} does not contain standard YAML frontmatter bounded by ---"]
    errors: list[str] = []
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("#") or line.startswith((" ", "\t")):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            errors.append(f"Skill file {path} contains invalid frontmatter syntax: {line!r}")
            continue
        values[key.strip()] = value.strip().strip("'\"")
    name = values.get("name")
    description = values.get("description")
    if not name:
        errors.append(f"Skill file {path} frontmatter is missing 'name'")
    elif name != path.parent.name or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        errors.append(f"Skill file {path} has an invalid or mismatched 'name'")
    if not description:
        errors.append(f"Skill file {path} frontmatter is missing 'description'")
    elif len(description) > 1024:
        errors.append(f"Skill file {path} 'description' exceeds 1024 characters")
    return errors

def main() -> int:
    print("Starting plugin verification and validation...")
    errors: list[str] = []
    for path in REQUIRED_FILES:
        if not path.is_file():
            errors.append(f"Missing required file/path: {path}")
    copilot = read_json(PACKAGE / "plugin.json", errors)
    codex = read_json(PACKAGE / ".codex-plugin/plugin.json", errors)
    claude = read_json(PACKAGE / ".claude-plugin/plugin.json", errors)
    for key in ("$schema", "name", "version", "description", "author"):
        if key not in copilot:
            errors.append(f"{PACKAGE / 'plugin.json'} is missing key: '{key}'")
    if copilot.get("name") != "security-logging-advisor":
        errors.append("Copilot plugin name must be security-logging-advisor.")
    expected_identity = (copilot.get("name"), copilot.get("version"))
    if (codex.get("name"), codex.get("version")) != expected_identity:
        errors.append("Codex and Copilot plugin identities must match.")
    if (claude.get("name"), claude.get("version")) != expected_identity:
        errors.append("Claude and Copilot plugin identities must match.")
    if codex.get("skills") not in {"./skills", "./skills/"}:
        errors.append("Codex manifest must reference the package skills directory.")
    interface = codex.get("interface")
    required_interface = {
        "displayName", "shortDescription", "longDescription", "developerName",
        "category", "capabilities", "defaultPrompt",
    }
    if not isinstance(interface, dict) or not required_interface <= interface.keys():
        errors.append("Codex manifest is missing required interface metadata.")
    elif not isinstance(interface["capabilities"], list) or not interface["capabilities"]:
        errors.append("Codex manifest must declare at least one interface capability.")
    elif not isinstance(interface["defaultPrompt"], list) or not interface["defaultPrompt"]:
        errors.append("Codex manifest must declare at least one default prompt.")
    skills = sorted((PACKAGE / "skills").glob("*/SKILL.md"))
    if not skills:
        errors.append("The package must contain at least one skill.")
    for skill in skills:
        errors.extend(check_skill(skill))
    if errors:
        print("\nValidation failed with errors:")
        for error in errors:
            print(f" - [ERROR] {error}")
        return 1
    print("\nAll checks passed successfully! Copilot, Codex, and Claude manifests plus skill frontmatter are valid.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
