"""Executable acceptance scenarios for the catalog-driven operator workflow."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest
from pytest_bdd import given, scenarios, then, when


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cops.catalog import CatalogError, plugin_records, validate_declared_command
from cops.validation import ValidationError, generate_marketplaces


scenarios("../../specs/features/portable_operator_workflow.feature")


@pytest.fixture
def context() -> dict[str, object]:
    return {}


@given("the canonical COPS package catalog")
def canonical_catalog(context):
    context["records"] = plugin_records(ROOT)


@when("I list the available cybersecurity packages")
def list_packages(context):
    context["result"] = subprocess.run(
        [sys.executable, "-m", "cops", "list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


@then("every catalog package is shown with offline, host, and live support states")
def catalog_packages_are_visible(context):
    result = context["result"]
    assert result.returncode == 0, result.stderr
    assert all(label in result.stdout for label in ("OFFLINE", "HOST", "LIVE"))
    for record in context["records"]:
        assert record.id in result.stdout
        assert record.support["offline_workflow"] in result.stdout
        assert record.support["host_installation"] in result.stdout
        assert record.support["live_integration"] in result.stdout


@when("I run each package's declared offline demo")
def run_demos(context):
    context["results"] = [
        subprocess.run(
            [sys.executable, "-m", "cops", "demo", record.id],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=record.package["demo"]["timeout_seconds"] + 5,
        )
        for record in context["records"]
    ]


@then("every demo succeeds without shell interpretation")
def demos_succeed(context):
    for result in context["results"]:
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.args[:4] == [sys.executable, "-m", "cops", "demo"]


@when("a package declares a command outside its own directory")
def escaping_command(context):
    record = context["records"][0]
    definition = {
        "command": ["$PYTHON", "../../scripts/agent/check.py"],
        "timeout_seconds": 10,
    }
    try:
        validate_declared_command(definition, record, ROOT)
    except CatalogError as error:
        context["error"] = error


@then("the package command is rejected before execution")
def escape_is_rejected(context):
    assert "error" in context
    assert "inside its package" in str(context["error"])


@given("a generated host index that differs from its canonical document")
def stale_index(context, tmp_path, monkeypatch):
    target = Path("generated") / "marketplace.json"
    destination = tmp_path / target
    destination.parent.mkdir(parents=True)
    original = json.dumps({"name": "stale"}) + "\n"
    destination.write_text(original, encoding="utf-8")
    monkeypatch.setattr(
        "cops.validation.marketplace_documents",
        lambda root: {target: {"name": "expected"}},
    )
    context.update(root=tmp_path, target=destination, original=original)


@when("generated host indexes are checked")
def check_generated_indexes(context):
    with pytest.raises(ValidationError) as captured:
        generate_marketplaces(context["root"], check=True)
    context["error"] = captured.value


@then("the stale index is reported without being rewritten")
def stale_index_reported(context):
    assert "generated host indexes are stale" in str(context["error"])
    assert context["target"].read_text(encoding="utf-8") == context["original"]
