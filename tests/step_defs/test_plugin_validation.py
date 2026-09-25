"""Executable package-manifest and dynamic-skill scenarios."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

from pytest_bdd import given, parsers, scenarios, then, when
import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PACKAGE = ROOT / "plugins/logging-telemetry/security-logging-advisor"
VALIDATOR = SOURCE_PACKAGE / "scripts/validate-plugin.py"
PACKAGE = Path("plugins/logging-telemetry/security-logging-advisor")

scenarios("../../specs/features/plugin_validation.feature")
scenarios("../../specs/features/edge_cases_validation.feature")


@pytest.fixture
def context():
    return {}


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path):
    old_cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(old_cwd)


@given("a valid categorized Security Logging Advisor package")
def valid_package():
    shutil.copytree(SOURCE_PACKAGE, PACKAGE)


@given(parsers.parse('a valid custom skill named "{name}"'))
def custom_skill(name):
    skill = PACKAGE / "skills" / name / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(f"---\nname: {name}\ndescription: Synthetic validation fixture.\n---\n# Fixture\n")


@when("the package validation script executes")
def execute_validation(context):
    result = subprocess.run(
        ["python3", str(VALIDATOR)], capture_output=True, text=True, check=False
    )
    context["result"] = result


def test_validator_runs_from_portable_package_root(tmp_path):
    package = tmp_path / "portable"
    shutil.copytree(SOURCE_PACKAGE, package)
    for native in (".claude-plugin", ".codex-plugin", "commands"):
        shutil.rmtree(package / native)
    result = subprocess.run(
        ["python3", "scripts/validate-plugin.py"], cwd=package,
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@then("the Copilot manifest must contain required identity keys")
def copilot_keys():
    manifest = json.loads((PACKAGE / "plugin.json").read_text())
    assert {"$schema", "name", "version", "description", "author"} <= manifest.keys()


@then("the Codex manifest must contain required interface metadata")
def codex_interface():
    codex = json.loads((PACKAGE / ".codex-plugin/plugin.json").read_text())
    assert codex["skills"] in {"./skills", "./skills/"}
    assert {
        "displayName",
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
        "capabilities",
        "defaultPrompt",
    } <= codex["interface"].keys()


@then("all host manifest identities must match")
def host_identities():
    copilot = json.loads((PACKAGE / "plugin.json").read_text())
    codex = json.loads((PACKAGE / ".codex-plugin/plugin.json").read_text())
    claude = json.loads((PACKAGE / ".claude-plugin/plugin.json").read_text())
    assert (codex["name"], codex["version"]) == (copilot["name"], copilot["version"])
    assert (claude["name"], claude["version"]) == (copilot["name"], copilot["version"])


@then("every packaged skill must contain name and description frontmatter")
def skill_frontmatter():
    for skill in (PACKAGE / "skills").glob("*/SKILL.md"):
        content = skill.read_text()
        assert content.startswith("---\nname:")
        assert "\ndescription:" in content.split("---", 2)[1]


@then("the custom skill should be validated")
def custom_validated(context):
    assert (PACKAGE / "skills/custom-audit/SKILL.md").is_file()
    assert context["result"].returncode == 0


@then("the validation should pass")
def validation_passes(context):
    result = context["result"]
    assert result.returncode == 0, result.stdout + result.stderr
