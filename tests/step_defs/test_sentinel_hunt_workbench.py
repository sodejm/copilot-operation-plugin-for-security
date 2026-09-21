"""Executable acceptance scenarios for the offline Sentinel Hunt Workbench."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest
from pytest_bdd import given, parsers, scenarios, then, when


ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins/detection-hunting/sentinel-hunt-workbench"
CLI = PLUGIN / "scripts/huntwb.py"

scenarios("../../specs/features/sentinel_hunt_workbench.feature")


@pytest.fixture
def context() -> dict[str, object]:
    return {}


def cli(*args: object, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), *map(str, args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def output(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.stdout, result.stderr
    return json.loads(result.stdout)


@given("the Sentinel Hunt Workbench package")
def sentinel_package(context):
    assert CLI.is_file()


@when("I validate the Sentinel hunt library")
def validate_library(context):
    context["result"] = cli("validate", "library")


@then("exactly 12 gold hunt definitions pass the contract")
def twelve_hunts_pass(context):
    result = context["result"]
    document = output(result)
    assert result.returncode == 0, result.stderr
    assert document["status"] == "passed"
    assert document["hunts"] == 12


@then("no live-service assurance claim is awarded")
def no_live_assurance(context):
    document = output(context["result"])
    assert document["offline_only"] is True
    package = json.loads((PLUGIN / "package.json").read_text(encoding="utf-8"))
    assert package["support"]["host_installation"] == "unverified"
    assert package["support"]["live_integration"] == "unverified"


@when(parsers.parse('I render hunt "{hunt_id}" with a raw KQL fragment parameter'))
def render_injection(context, hunt_id, tmp_path):
    parameters = json.loads((PLUGIN / "examples/h01-parameters.json").read_text(encoding="utf-8"))
    parameters["workspace_id"] = "00000000-0000-4000-8000-000000000001 | take 1"
    path = tmp_path / "unsafe-parameters.json"
    path.write_text(json.dumps(parameters), encoding="utf-8")
    context["result"] = cli(
        "render", hunt_id, "--surface", "sentinel_analytics", "--params", path
    )


@then("rendering fails closed as a content validation error")
def injection_fails_closed(context):
    result = context["result"]
    assert result.returncode == 2
    document = json.loads(result.stderr)
    assert document["status"] == "failed"
    assert document["error_type"] == "ContentError"


@when(parsers.parse("I run the Sentinel hunt test suite with seed {seed:d}"))
def run_adversarial_suite(context, seed):
    context["result"] = cli("test", "library", "--seed", seed, timeout=120)


@then(parsers.parse("{count:d} curated cases pass"))
def curated_cases_pass(context, count):
    document = output(context["result"])
    assert context["result"].returncode == 0, context["result"].stderr
    assert document["curated_cases"] == count


@then(parsers.parse("at least {count:d} generated perturbations pass"))
def perturbations_pass(context, count):
    document = output(context["result"])
    assert document["generated_perturbations"] >= count


@then("all critical semantic mutations are caught")
def mutations_are_caught(context):
    document = output(context["result"])
    assert document["critical_mutations_caught"] == document["critical_mutations_total"]
    assert document["mutation_score_percent"] >= 95


@when("I verify the generated platform adapters")
def verify_adapters(context):
    context["result"] = cli("verify-adapters")


@then("the adapter hashes match their canonical sources")
def adapters_match(context):
    result = context["result"]
    document = output(result)
    assert result.returncode == 0, result.stderr
    assert document["status"] == "passed"
    assert document["canonical_skill_count"] == 6
    assert document["platform_count"] == 3
    assert document["generated_file_count"] == 29
    assert len(document["canonical_skill_bundle_sha256"]) == 64
    assert len(document["manifest_sha256"]) == 64


@when("I create a release qualification report")
def release_report(context):
    context["result"] = cli("release-report")


@then("the report is not offline qualified without two human approvals")
def qualification_withheld(context):
    document = output(context["result"])
    assert context["result"].returncode == 0, context["result"].stderr
    assert document["status"] == "qualification_withheld"
    assert document["qualification_state"] != "offline_qualified"
    assert document["gates"]["human_approvals"]["status"] == "pending"


@then("the report marks cross-platform model evaluation as pending")
def model_evaluation_pending(context):
    document = output(context["result"])
    assert document["gates"]["model_evaluation"]["status"] == "pending"
    assert document["assurance"]["microsoft_service_execution"] == "not_performed"
