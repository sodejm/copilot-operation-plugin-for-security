"""Regression coverage for the adapted PARK validation gate."""

import subprocess
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "agent"))
import check as gate
from repository_files import repository_files

scenarios("../../specs/features/repository_conformance.feature")


@pytest.fixture
def context(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    return {"root": root}


def put(root, name, contents="answer = 42\n"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


@given("a Git checkout with tracked, new, and ignored Python files")
def git_sources(context):
    root = context["root"]
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    put(root, ".gitignore", ".venv/\nignored/\n")
    for name in ("tracked.py", "new.py", "ignored/retained.py", ".venv/broken.py"):
        put(root, name)
    subprocess.run(["git", "add", "-f", "tracked.py", "ignored/retained.py"], cwd=root, check=True)


@when("repository sources are enumerated")
def enumerate_sources(context):
    context["files"] = {path.relative_to(context["root"]).as_posix() for path in repository_files(context["root"])}


@then("tracked and new sources are included")
def included(context):
    assert {"tracked.py", "new.py", "ignored/retained.py"} <= context["files"]


@then("ignored local artifacts are excluded")
def excluded(context):
    assert ".venv/broken.py" not in context["files"]
    assert not any(name.startswith(".git/") for name in context["files"])


@given("a source archive with symlinks to external files and directories")
def symlink_sources(context):
    root = context["root"]
    external = root.parent / "external"
    put(external, "outside.py")
    put(root, "own.py")
    (root / "linked.py").symlink_to(external / "outside.py")
    (root / "linked_dir").symlink_to(external, target_is_directory=True)


@then("only the archive's own source is included")
def archive_only(context):
    assert context["files"] == {"own.py"}


@given("a source archive with valid project Python and an invalid virtual environment")
def archive_sources(context):
    put(context["root"], "valid.py")
    put(context["root"], ".venv/invalid.py", "this is invalid Python !\n")


@when("Python sources are validated")
def validate(context):
    context["valid"] = gate.validate_python(context["root"])


@then("Python validation passes")
def passes(context):
    assert context["valid"]


@when("a new invalid project source is added")
def add_invalid(context):
    put(context["root"], "invalid.py", "this is invalid Python !\n")


@then("Python validation fails")
def fails(context):
    assert not gate.validate_python(context["root"])


@given("the COPS command and model guidance")
def model_guidance(context):
    context["command"] = (ROOT / "plugins/logging-telemetry/security-logging-advisor/commands/security-logging-advisor.md").read_text()
    context["guidance"] = (ROOT / "plugins/logging-telemetry/security-logging-advisor/docs/model-routing.md").read_text()


@then("the command does not pin a model")
def no_model(context):
    frontmatter = context["command"].split("---", 2)[1]
    assert not any(line.strip().startswith("model:") for line in frontmatter.splitlines())


@then("model guidance requires the live host catalog")
def live_catalog(context):
    assert "live model catalog" in context["guidance"]
    assert "COPS pins neither" in context["guidance"]


@given("an aggregate gate with a failing plugin validation command")
def failing_gate(context, monkeypatch):
    context["commands"] = []

    def fake_run(command):
        context["commands"].append(command)
        return not any(item.endswith("validate-plugin.py") for item in command)

    monkeypatch.setattr(gate, "run", fake_run)
    monkeypatch.setattr(gate, "validate_python", lambda: True)


@when("the aggregate gate runs")
def aggregate(context):
    context["exit"] = gate.main()


@then("the gate returns failure and still runs the scenario suite")
def aggregate_failed(context):
    assert context["exit"] == 1
    assert any("pytest" in command for command in context["commands"])
