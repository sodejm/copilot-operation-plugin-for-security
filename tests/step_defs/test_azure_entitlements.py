# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Executable acceptance scenarios for the offline Azure profile."""
import json
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins/detection-hunting/attack-path-workbench"
sys.path.insert(0, str(PLUGIN))
sys.path.insert(0, str(PLUGIN / "tests"))
from azure_fixtures import write_bundle
from test_azure_paths import (
    NOW,
    SECRET,
    VAULT,
    S,
    T,
    base,
    deployment,
    execution,
    role,
)
from test_azure_sdk_cli import run_cli

scenarios("../../specs/features/azure_entitlements.feature")


@pytest.fixture
def azure_context(tmp_path):
    return {"root": tmp_path, "kwargs": {}}


@given("an Azure bundle with VM execution prerequisites")
def vm_bundle(azure_context):
    g, resource = execution("Microsoft.Compute/virtualMachines",
                            ["Microsoft.Compute/virtualMachines/write", "Microsoft.Compute/virtualMachines/extensions/write"],
                            ["vm_agent", "network", "token_endpoint"])
    azure_context.update(graph=g, resource=resource)


@given("the runtime assumptions are absent")
def absent_runtime(azure_context):
    azure_context["graph"].scenario["runtime"] = {}


@given("acquisition is incomplete")
def incomplete(azure_context):
    azure_context["kwargs"]["status"] = "partial"


@given("an evidence checksum is invalid")
def tamper(azure_context):
    azure_context["tamper"] = True


@given("an Azure bundle with two independent secret access grants")
def alternate_grants(azure_context):
    g = base()
    role(g, "user", data=[SECRET], scope=VAULT, suffix="first")
    role(g, "user", data=[SECRET], scope=VAULT, suffix="second")
    azure_context["graph"] = g


@when("the Azure analyzer evaluates the bundle")
def analyze(azure_context):
    manifest = write_bundle(azure_context["root"], azure_context["graph"], **azure_context["kwargs"])
    if azure_context.get("tamper"):
        value = json.loads(manifest.read_text())
        value["sources"][0]["sha256"] = "0" * 64
        manifest.write_text(json.dumps(value))
    output = azure_context["root"] / "report"
    azure_context["output"] = output
    azure_context["result"] = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW, "--output", output,
                                      *azure_context.get("cli_args", ()))
    if azure_context["result"].returncode == 0:
        azure_context["report"] = json.loads((output / "report.json").read_text())


@then("a VM execution path is modelled reachable")
def reachable(azure_context):
    assert azure_context["result"].returncode == 0, azure_context["result"].stderr
    assert any(p["classification"] == "modelled_reachable" and any(s["rule"] == "vm_execution" for s in p["steps"])
               for p in azure_context["report"]["paths"])


@then("every path evidence reference exists in the evidence ledger")
def linked_evidence(azure_context):
    ledger = {r["record_id"] for r in azure_context["report"]["evidence_ledger"]["records"]}
    assert all(set(p["evidence"]) <= ledger for p in azure_context["report"]["paths"])


@then("VM execution remains conditional")
def conditional(azure_context):
    assert azure_context["result"].returncode == 0, azure_context["result"].stderr
    assert any(p["classification"] == "conditional" and any(s["rule"] == "vm_execution" for s in p["steps"])
               for p in azure_context["report"]["paths"])
    assert not any(p["classification"] == "modelled_reachable" for p in azure_context["report"]["paths"])


@then("no path is modelled reachable")
def unknown(azure_context):
    assert azure_context["result"].returncode == 0, azure_context["result"].stderr
    assert not any(p["classification"] == "modelled_reachable" for p in azure_context["report"]["paths"])
    assert any(r["quality"] for r in azure_context["report"]["evidence_ledger"]["records"])


@then("integrity failure prevents a completion marker")
def failed(azure_context):
    assert azure_context["result"].returncode == 2
    assert "Azure input or output validation failed" in azure_context["result"].stderr
    assert not (azure_context["output"] / "completion.json").exists()


@then("each single removal leaves a reachable path")
def survives(azure_context):
    assert azure_context["result"].returncode == 0, azure_context["result"].stderr
    remediation = azure_context["report"]["remediation"]
    assert remediation["actions"]
    assert not remediation["global_minimum_claimed"]
    assert all(c["reachable_after"] > 0 and not c["broken_paths"] for c in remediation["actions"])


@given("an explicit Azure collection scope")
def collection_scope(azure_context):
    scope = azure_context["root"] / "scope.json"
    scope.write_text(json.dumps({"schema_version": "attackpath.azure.scope/v1", "tenants": [{"id": T, "scopes": [S]}]}))
    azure_context["scope"] = scope


@when("the Azure collection plan is generated")
def collect(azure_context):
    output = azure_context["root"] / "plan"
    result = run_cli("plan-azure-collection", "--scope-file", azure_context["scope"], "--output", output)
    assert result.returncode == 0, result.stderr
    azure_context["plan"] = json.loads((output / "collection-plan.json").read_text())


@then("every planned request is a versioned read operation with a permission and reference")
def read_only(azure_context):
    assert azure_context["plan"]["requests"]
    assert all((r["method"] == "GET" or (r["family"] == "resource_inventory" and r["method"] == "POST")) and r["api"] and r["permission"] and
               r["reference"].startswith("https://learn.microsoft.com/") for r in azure_context["plan"]["requests"])


@given("an Azure bundle with ARM deployment prerequisites")
def deployment_bundle(azure_context):
    g, resource = deployment()
    azure_context.update(graph=g, resource=resource)


@given("deployment validation is excluded from the role")
def excluded_deployment(azure_context):
    azure_context["graph"].rows("role_definitions")[0].properties["permissions"][0]["notActions"] = [
        "Microsoft.Resources/deployments/validate/action"]


@then("an ARM deployment path is modelled reachable")
def deployment_reachable(azure_context):
    assert azure_context["result"].returncode == 0, azure_context["result"].stderr
    assert any(p["classification"] == "modelled_reachable" and any(s["rule"] == "arm_deployment" for s in p["steps"])
               for p in azure_context["report"]["paths"])


@then("ARM deployment remains unknown because alternate grants are unresolved")
def deployment_unknown(azure_context):
    assert azure_context["result"].returncode == 0, azure_context["result"].stderr
    paths = azure_context["report"]["paths"]
    assert not any(p["classification"] == "modelled_reachable" for p in paths)
    candidates = [p for p in paths if any(s["rule"] == "arm_deployment" for s in p["steps"])]
    assert candidates
    assert all(p["classification"] == "unknown" and "grant_coverage_unknown" in p["uncertainty"] for p in candidates)


@given("an Azure bundle with a source exceeding a file, line, depth, or combined record limit")
def bounded_bundle(azure_context):
    azure_context["graph"] = base()
    azure_context["limit_cases"] = (("--max-file-bytes", "100"),
                                    ("--max-line-bytes", "10"),
                                    ("--max-json-depth", "1"),
                                    ("--max-records", "1"))


@then("ingestion rejects the input without a completion marker")
def bounded_bundle_rejected(azure_context):
    manifest = azure_context["root"] / "manifest.json"
    assert manifest.is_file()
    for index, pair in enumerate(azure_context["limit_cases"]):
        output = azure_context["root"] / f"bounded-{index}"
        result = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW, "--output", output, *pair)
        assert result.returncode == 2, result.stderr
        assert not (output / "completion.json").exists()


@given("an Azure bundle whose manifest permits a larger bounded input")
def manifest_limit(azure_context):
    azure_context["graph"] = base()
    azure_context["kwargs"]["limits"] = {"file_bytes": 16 * 1024 * 1024}
    azure_context["cli_args"] = ("--max-file-bytes", "100")


@when("the Azure analyzer evaluates the bundle with a smaller command limit")
def analyze_with_limit(azure_context):
    analyze(azure_context)


@then("the smaller limit is enforced before report completion")
def smaller_limit_rejected(azure_context):
    assert azure_context["result"].returncode == 2
    assert not (azure_context["output"] / "completion.json").exists()
    accepted = run_cli("analyze-azure", "--input", azure_context["root"] / "manifest.json",
                       "--as-of", NOW, "--output", azure_context["root"] / "accepted")
    assert accepted.returncode == 0, accepted.stderr
