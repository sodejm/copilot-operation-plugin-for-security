"""Acceptance test step definitions for capability reconciliation and truth-in-advertising."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.capabilities import (
    CapabilityTruthError,
    audit_capabilities,
    build_capability_registry,
)

ROOT = Path(__file__).resolve().parents[2]

scenarios("../../specs/features/capability_reconciliation.feature")


@pytest.fixture
def audit_context():
    return {}


@given("the current COPS repository catalog")
def current_catalog(audit_context):
    audit_context["root"] = ROOT


@when("the capability truth-in-advertising auditor is executed")
def run_auditor(audit_context):
    try:
        registry = build_capability_registry(audit_context["root"])
        audit_context["summary"] = audit_capabilities(audit_context["root"], registry_data=registry)
        audit_context["registry"] = registry
        audit_context["error"] = None
    except CapabilityTruthError as err:
        audit_context["summary"] = None
        audit_context["error"] = err


@then(parsers.parse('the audit succeeds with status "{status}"'))
def verify_audit_status(audit_context, status):
    assert audit_context["summary"] is not None
    assert audit_context["summary"]["status"] == status


@then(parsers.parse("exactly {count:d} plugins are reconciled"))
def verify_plugin_count(audit_context, count):
    assert audit_context["summary"]["by_kind"]["plugin"] == count


@then(parsers.parse("exactly {count:d} specialist profiles are reconciled"))
def verify_specialist_count(audit_context, count):
    assert audit_context["summary"]["by_kind"]["specialist"] == count


@then(parsers.parse("exactly {count:d} scenarios are reconciled"))
def verify_scenario_count(audit_context, count):
    assert audit_context["summary"]["by_kind"]["scenario"] == count


@then(parsers.parse('exactly {count:d} capabilities claim "{mode}" mode'))
def verify_mode_count(audit_context, count, mode):
    assert audit_context["summary"]["by_mode"].get(mode, 0) == count


@given("the reconciled capability registry is loaded")
def load_reconciled_registry(audit_context):
    audit_context["registry"] = build_capability_registry(ROOT)


@when(parsers.parse('querying capabilities with mode "{mode}"'))
def query_by_mode(audit_context, mode):
    caps = audit_context["registry"]["capabilities"]
    audit_context["queried_caps"] = [c for c in caps if c["mode"] == mode]


@then(parsers.parse("at least {min_count:d} {mode} capabilities are returned"))
def verify_min_mode_results(audit_context, min_count, mode):
    assert len(audit_context["queried_caps"]) >= min_count


@given("a capability entry claiming mode \"live-validated\" without verified evidence")
def setup_unverified_live_claim(audit_context):
    reg = build_capability_registry(ROOT)
    # Clone and inject a false live claim
    bad_reg = copy.deepcopy(reg)
    bad_reg["capabilities"][0]["mode"] = "live-validated"
    bad_reg["capabilities"][0]["live_evidence_verified"] = False
    audit_context["candidate_registry"] = bad_reg


@when("capability audit is executed on the candidate registry")
def audit_candidate_registry(audit_context):
    target = audit_context.get("root", ROOT)
    try:
        audit_context["summary"] = audit_capabilities(target, registry_data=audit_context["candidate_registry"])
        audit_context["error"] = None
    except CapabilityTruthError as err:
        audit_context["summary"] = None
        audit_context["error"] = err



@then(parsers.parse('the audit fails with error code "{code}"'))
def verify_audit_error(audit_context, code):
    assert audit_context["error"] is not None
    assert audit_context["error"].code == code


@given('a plugin package claiming "live_integration" as "validated" without live evidence')
def setup_unverified_live_integration(tmp_path, audit_context):
    # Setup mock root
    mock_catalog = tmp_path / "catalog"
    mock_catalog.mkdir(parents=True)
    (mock_catalog / "plugins.json").write_text(
        (ROOT / "catalog" / "plugins.json").read_text(encoding="utf-8")
    )
    (mock_catalog / "scenarios.json").write_text(
        (ROOT / "catalog" / "scenarios.json").read_text(encoding="utf-8")
    )
    mock_schemas = mock_catalog / "schemas"
    mock_schemas.mkdir(parents=True)
    for sf in (ROOT / "catalog" / "schemas").glob("*.json"):
        (mock_schemas / sf.name).write_text(sf.read_text(encoding="utf-8"))

    # Copy agents
    mock_agents = tmp_path / "agents"
    mock_agents.mkdir(parents=True)
    (mock_agents / "registry.json").write_text(
        (ROOT / "agents" / "registry.json").read_text(encoding="utf-8")
    )

    # Copy plugins
    plugins_index = json.loads((ROOT / "catalog" / "plugins.json").read_text(encoding="utf-8"))
    for p in plugins_index["plugins"]:
        pkg_dir = tmp_path / p["path"]
        pkg_dir.mkdir(parents=True)
        real_pkg = json.loads((ROOT / p["path"] / "package.json").read_text(encoding="utf-8"))
        if p["id"] == "security-logging-advisor":
            real_pkg["support"]["live_integration"] = "validated"
        (pkg_dir / "package.json").write_text(json.dumps(real_pkg), encoding="utf-8")

    audit_context["root"] = tmp_path
    reg = build_capability_registry(tmp_path)
    audit_context["candidate_registry"] = reg


@given("a capability entry with empty truth boundaries")
def setup_empty_truth_boundary(audit_context):
    reg = build_capability_registry(ROOT)
    bad_reg = copy.deepcopy(reg)
    bad_reg["capabilities"][0]["truth_boundaries"] = ""
    audit_context["candidate_registry"] = bad_reg
