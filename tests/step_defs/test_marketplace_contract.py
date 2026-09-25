from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytest_bdd import given, parsers, scenarios, then, when


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "agent"))

from validate_marketplace import ValidationError, validate_finding_document, validate_marketplace
import export_portable
import install_prerequisites
from cops.prerequisites import PrerequisiteError, process_tools, validate_prerequisites
from cops.validation import ValidationError as PackageValidationError, validate_agent_plugin_manifest
from cops.portable import export_portable_package
from cops.mcp_validation import MCPValidationError, MCP_SCHEMA, validate_mcp_configuration


scenarios("../../specs/features/marketplace_portability.feature")


@pytest.fixture
def context() -> dict[str, object]:
    return {}


def verified_example() -> dict[str, object]:
    return json.loads((ROOT / "catalog/examples/verified-finding.json").read_text(encoding="utf-8"))


@given("the repository marketplace catalog")
def repository_catalog(context):
    context["action"] = validate_marketplace


@given("a package manifest with an unknown top-level field")
def unknown_portable_field(context):
    context["manifest"] = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "fixture-plugin",
        "install": "./setup.sh",
    }


@given("a prerequisite package with shell syntax")
def unsafe_prerequisite(context):
    context["prerequisites"] = {
        "schema_version": "1.0",
        "tools": [{"id": "fixture", "command": "fixture", "packages": {"brew": "fixture;echo"}}],
    }


@given("a package with Claude Code and Codex host files")
def host_package(context, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "plugin.json").write_text(json.dumps({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "fixture-plugin",
        "extensions": {"com.sodejm.copse": {}},
    }), encoding="utf-8")
    skill = source / "skills" / "fixture-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: fixture-skill\ndescription: Fixture skill.\n---\n\nRun a check.\n",
        encoding="utf-8",
    )
    namespace = source / "com.sodejm.copse"
    namespace.mkdir()
    (namespace / "prerequisites.json").write_text(
        '{"schema_version":"1.0","tools":[]}', encoding="utf-8"
    )
    for native in (".claude-plugin", ".codex-plugin", "agents"):
        (source / native).mkdir()
        (source / native / "fixture.json").write_text("{}", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    context["source"] = source
    context["destination"] = tmp_path / "portable"


@given("a package with an unreviewed package-root entry")
def unreviewed_package_entry(context, tmp_path):
    host_package(context, tmp_path)
    (context["source"] / "new-root-directory").mkdir()


@given("a finding with complete current supporting evidence")
def complete_finding(context):
    context["document"] = verified_example()


@given("a limited-confidence finding without an uncertainty statement")
def limited_finding(context):
    document = verified_example()
    finding = document["findings"][0]
    finding["verification"] = "partially-verified"
    finding["confidence"] = "limited"
    finding["coverage"] = "partial"
    finding["uncertainty"] = ""
    context["document"] = document


@given("a merged delivery claim without merge evidence")
def unsupported_delivery(context):
    document = verified_example()
    document["findings"][0]["delivery_claims"] = [
        {"state": "merged", "evidence_ids": ["validation-command"]}
    ]
    context["document"] = document


@when("the marketplace contract is validated")
def validate_catalog(context):
    context["action"]()
    context["accepted"] = True


@when("the Agent Plugins v1.0.0 manifest is validated")
def validate_portable_manifest(context):
    with pytest.raises(PackageValidationError) as failure:
        validate_agent_plugin_manifest(context["manifest"], "fixture/plugin.json")
    context["error"] = str(failure.value)


@when("the prerequisite declaration is validated")
def validate_prerequisite_fixture(context):
    with pytest.raises(PrerequisiteError) as failure:
        validate_prerequisites(context["prerequisites"], "fixture/prerequisites.json")
    context["error"] = str(failure.value)


@when("the package is exported for Agent Plugins v1.0.0")
def export_fixture(context):
    try:
        export_portable_package(context["source"], context["destination"])
    except PackageValidationError as error:
        context["error"] = str(error)


@when("the finding contract is validated")
def validate_finding(context):
    try:
        validate_finding_document(context["document"], "test-finding")
    except ValidationError as error:
        context["error"] = str(error)
    else:
        context["accepted"] = True


@then("every package is categorized and indexed for each supported host")
def catalog_accepted(context):
    assert context["accepted"] is True


@then("the portable manifest is rejected")
def portable_manifest_rejected(context):
    assert "unknown Agent Plugins fields" in context["error"]


@then("the prerequisite declaration is rejected")
def prerequisites_rejected(context):
    assert "safe package id" in context["error"]


@then("the portable package keeps skills and namespaced extensions")
def portable_content(context):
    destination = context["destination"]
    assert (destination / "skills/fixture-skill/SKILL.md").is_file()
    assert (destination / "com.sodejm.copse/prerequisites.json").is_file()


@then("the portable package excludes native host files")
def native_excluded(context):
    destination = context["destination"]
    assert not (destination / ".claude-plugin").exists()
    assert not (destination / ".codex-plugin").exists()


@then("the portable package keeps optional Claude agents")
def claude_agents_kept(context):
    assert (context["destination"] / "agents/fixture.json").is_file()


@then("the portable export is rejected")
def portable_export_rejected(context):
    assert "unreviewed root entries" in context["error"]
    assert not context["destination"].exists()


@then("the finding is accepted")
def finding_accepted(context):
    assert context["accepted"] is True


@then(parsers.parse("the finding is rejected for {reason}"))
def finding_rejected(context, reason):
    assert "error" in context
    expected = {
        "missing uncertainty": "requires a plain-language uncertainty statement",
        "missing delivery evidence": "missing evidence for delivery state merged",
    }
    assert expected[reason] in context["error"]


def test_verified_high_confidence_rejects_stale_evidence():
    document = copy.deepcopy(verified_example())
    document["findings"][0]["evidence"][0]["freshness"] = "stale"
    document["findings"][0]["uncertainty"] = "The evidence is stale."
    with pytest.raises(ValidationError, match="require current evidence"):
        validate_finding_document(document, "test-finding")


def test_portable_manifest_accepts_minimal_spec_document():
    validate_agent_plugin_manifest({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "fixture-plugin",
    }, "fixture/plugin.json")


def test_prerequisite_installer_requires_explicit_install():
    tool = {"id": "jq", "command": "jq", "packages": {"brew": "jq"}}
    calls = []
    installed = False

    def which(command):
        return "/usr/bin/brew" if command == "brew" else ("/usr/bin/jq" if installed else None)

    def run(command, *, check):
        nonlocal installed
        calls.append((command, check))
        installed = True
        return type("Result", (), {"returncode": 0})()

    assert process_tools([tool], platform="darwin", which=which, run=run) == ["jq"]
    assert calls == []
    assert process_tools([tool], dry_run=True, platform="darwin", which=which, run=run) == ["jq"]
    assert calls == []
    assert process_tools([tool], install=True, platform="darwin", which=which, run=run) == []
    assert calls == [(["brew", "install", "jq"], False)]


def test_prerequisite_installer_detects_failed_install():
    tool = {"id": "jq", "command": "jq", "packages": {"brew": "jq"}}
    with pytest.raises(PrerequisiteError, match="did not provide"):
        process_tools([tool], install=True, platform="darwin",
                      which=lambda name: "/usr/bin/brew" if name == "brew" else None,
                      run=lambda *args, **kwargs: type("Result", (), {"returncode": 0})())


def test_portable_export_rejects_symlinks(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "plugin.json").symlink_to(tmp_path / "outside.json")
    with pytest.raises(PackageValidationError, match="does not accept symlinks"):
        export_portable_package(source, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_portable_export_preserves_valid_mcp_configuration(context, tmp_path):
    host_package(context, tmp_path)
    mcp = {
        "$schema": MCP_SCHEMA,
        "mcpServers": {
            "local": {"type": "stdio", "command": "python3", "cwd": "${PLUGIN_ROOT}"},
            "remote": {"type": "streamable-http", "url": "https://example.org/mcp"},
        },
    }
    (context["source"] / "mcp.json").write_text(json.dumps(mcp), encoding="utf-8")
    subprocess.run(["git", "-C", str(context["source"]), "add", "mcp.json"], check=True)
    export_portable_package(context["source"], context["destination"])
    assert json.loads((context["destination"] / "mcp.json").read_text(encoding="utf-8")) == mcp


def test_portable_export_excludes_untracked_nested_files(context, tmp_path):
    host_package(context, tmp_path)
    secret = context["source"] / "skills" / "fixture-skill" / ".env"
    secret.write_text("PRIVATE_TOKEN=fixture", encoding="utf-8")
    export_portable_package(context["source"], context["destination"])
    assert not (context["destination"] / "skills" / "fixture-skill" / ".env").exists()


def test_portable_export_rejects_broken_relative_link(context, tmp_path):
    host_package(context, tmp_path)
    (context["source"] / "README.md").write_text(
        "[source-only](package.json)\n", encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(context["source"]), "add", "README.md"], check=True)
    with pytest.raises(PackageValidationError, match="broken portable documentation link"):
        export_portable_package(context["source"], context["destination"])
    assert not context["destination"].exists()


def test_portable_export_cleans_partial_output(monkeypatch, tmp_path):
    output = tmp_path / "packages"
    monkeypatch.setattr(export_portable, "validate_repository", lambda root: None)

    def fail_after_first_package(stage):
        (stage / "first-package").mkdir()
        raise PackageValidationError("later package failed")

    monkeypatch.setattr(export_portable, "export_all", fail_after_first_package)
    monkeypatch.setattr(sys, "argv", ["export_portable.py", "--output", str(output)])
    assert export_portable.main() == 1
    assert not output.exists()
    assert not list(tmp_path.glob(".copse-agent-plugins-*"))


def test_prerequisite_install_preflights_all_tools():
    tools = [
        {"id": "first", "command": "first", "packages": {"brew": "first"}},
        {"id": "later", "command": "later", "packages": {"winget": "later"}},
    ]
    calls = []
    with pytest.raises(PrerequisiteError, match="no supported installed package manager"):
        process_tools(tools, install=True, platform="darwin",
                      which=lambda name: "/usr/bin/brew" if name == "brew" else None,
                      run=lambda *args, **kwargs: calls.append(args))
    assert calls == []


def test_prerequisite_cli_preflights_every_selected_plugin(monkeypatch):
    records = [SimpleNamespace(id=name, path=name) for name in ("first", "later")]
    monkeypatch.setattr(install_prerequisites, "plugin_records", lambda root: records)
    monkeypatch.setattr(install_prerequisites, "load_json",
                        lambda path, root: {"id": path.parts[-3]})
    monkeypatch.setattr(install_prerequisites, "validate_prerequisites",
                        lambda document, location: [{"id": document["id"],
                                                     "command": document["id"],
                                                     "packages": {}}])
    monkeypatch.setattr(install_prerequisites.shutil, "which", lambda command: None)
    calls = []

    def preflight(tool, platform):
        calls.append(tool["id"])
        if tool["id"] == "later":
            raise PrerequisiteError("unsupported later tool")
        return ["brew", "install", "first"]

    monkeypatch.setattr(install_prerequisites, "install_command", preflight)
    monkeypatch.setattr(install_prerequisites, "process_tools",
                        lambda *args, **kwargs: pytest.fail("install began before global preflight"))
    monkeypatch.setattr(sys, "argv", ["install_prerequisites.py", "--install"])
    assert install_prerequisites.main() == 1
    assert calls == ["first", "later"]


@pytest.mark.parametrize("env", [{"plugin_root": "/tmp"}, {"TOKEN": "a", "token": "b"}])
def test_mcp_validator_rejects_case_insensitive_env_collisions(tmp_path, env):
    server = {"type": "stdio", "command": "python3", "env": env}
    with pytest.raises(MCPValidationError, match="reserved keys"):
        validate_mcp_configuration({"$schema": MCP_SCHEMA, "mcpServers": {"bad": server}},
                                   "mcp.json", tmp_path)


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_mcp_validator_requires_relative_command_file(tmp_path, kind):
    if kind == "directory":
        (tmp_path / "command").mkdir()
    server = {"type": "stdio", "command": "./command"}
    with pytest.raises(MCPValidationError, match="package file"):
        validate_mcp_configuration({"$schema": MCP_SCHEMA, "mcpServers": {"bad": server}},
                                   "mcp.json", tmp_path)


@pytest.mark.parametrize("server", [
    {"type": "stdio", "command": "../escape"},
    {"type": "streamable-http", "url": "http://example.org/mcp"},
    {"type": "sse", "url": "https://user:pass@example.org/mcp"},
    {"type": "streamable-http", "url": "https://example.org\\@other.example/mcp"},
    {"type": "streamable-http", "url": "https://exa mple.org/mcp"},
])
def test_mcp_validator_rejects_unsafe_server(tmp_path, server):
    with pytest.raises(MCPValidationError):
        validate_mcp_configuration({"$schema": MCP_SCHEMA, "mcpServers": {"unsafe": server}},
                                   "mcp.json", tmp_path)
