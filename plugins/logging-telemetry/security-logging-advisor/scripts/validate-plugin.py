#!/usr/bin/env python3
"""Validate the Security Logging Advisor in a checkout or portable package."""
from __future__ import annotations
import json
from pathlib import Path
import re

SOURCE_PACKAGE = Path("plugins/logging-telemetry/security-logging-advisor")
REQUIRED_FILES = [
    "plugin.json",
    "agents/security-logging-advisor.agent.md",
    "com.github.copilot/agents/security-logging-advisor.agent.md",
    "com.github.copilot/commands/security-logging-advisor.md",
    "skills/repository-context/scripts/collect-repository-context.py",
    "docs/INSTALL.md", "docs/ENTERPRISE_ROLLOUT.md",
    "docs/SECURITY_PRIVACY.md", "docs/TROUBLESHOOTING.md",
    "docs/MAINTAINERS.md", "CHANGELOG.md",
]
NATIVE_FILES = [
    ".codex-plugin/plugin.json",
    ".claude-plugin/plugin.json",
    "commands/security-logging-advisor.md",
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
    if SOURCE_PACKAGE.is_dir():
        package = SOURCE_PACKAGE
        native = True
    elif Path("plugin.json").is_file():
        package = Path(".")
        native = False
    else:
        package = SOURCE_PACKAGE
        native = True
    errors: list[str] = []
    for relative in REQUIRED_FILES + (NATIVE_FILES if native else []):
        path = package / relative
        if not path.is_file():
            errors.append(f"Missing required file/path: {path}")
    copilot = read_json(package / "plugin.json", errors)
    for key in ("$schema", "name", "version", "description", "author"):
        if key not in copilot:
            errors.append(f"{package / 'plugin.json'} is missing key: '{key}'")
    if copilot.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json":
        errors.append("The package manifest must use the Agent Plugins v1.0.0 schema.")
    if copilot.get("name") != "security-logging-advisor":
        errors.append("Plugin name must be security-logging-advisor.")
    if native:
        codex = read_json(package / ".codex-plugin/plugin.json", errors)
        claude = read_json(package / ".claude-plugin/plugin.json", errors)
        expected_identity = (copilot.get("name"), copilot.get("version"))
        if (codex.get("name"), codex.get("version")) != expected_identity:
            errors.append("Codex and portable plugin identities must match.")
        if (claude.get("name"), claude.get("version")) != expected_identity:
            errors.append("Claude and portable plugin identities must match.")
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
    skills = sorted((package / "skills").glob("*/SKILL.md"))
    if not skills:
        errors.append("The package must contain at least one skill.")
    for skill in skills:
        errors.extend(check_skill(skill))
    if errors:
        print("\nValidation failed with errors:")
        for error in errors:
            print(f" - [ERROR] {error}")
        return 1
    print("\nAll checks passed successfully! Package structure and skill frontmatter are valid.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
