# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Executable Entra freshness acceptance scenarios."""

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "plugins/identity-access/entra-identity-workbench"
sys.path.insert(0, str(PLUGIN_ROOT))

from entrawb.analysis import analyze_identity_graph
from entrawb.graph import build_identity_graph
from entrawb.ingestion import ingest_tenant_export
from entrawb.reporting import render_json_report

scenarios("../../specs/features/entra_identity_freshness.feature")
MANIFEST = PLUGIN_ROOT / "fixtures/tenants/contoso-corp/manifest.json"


@pytest.fixture
def state():
    return {}


@given("a complete Entra fixture export")
def complete_export(state):
    state["manifest"], state["sources"] = ingest_tenant_export(MANIFEST)


@given("an Entra fixture export without an OAuth grant entry")
def missing_export(state):
    complete_export(state)
    state["manifest"]["sources"] = [
        entry for entry in state["manifest"]["sources"] if entry["source_id"] != "oauth_grants"
    ]
    state["sources"].pop("oauth_grants")


@given("an Entra fixture export with partial OAuth grant coverage")
def partial_export(state):
    complete_export(state)
    for entry in state["manifest"]["sources"]:
        if entry["source_id"] == "oauth_grants":
            entry["completeness"] = "partial"


def assess(state, when):
    graph = build_identity_graph(state["manifest"], state["sources"], as_of=when)
    state["graph"] = graph
    state["report"] = render_json_report(graph, analyze_identity_graph(graph))


@when("the analyst assesses it six hours after export")
def assess_recent(state):
    assess(state, datetime(2026, 9, 30, 18, tzinfo=UTC))


@when("the analyst assesses it forty eight hours after export")
def assess_stale(state):
    assess(state, datetime(2026, 10, 2, 12, tzinfo=UTC))


@then("the Entra report contains seven hypotheses supported by fresh sources")
def fresh_hypotheses(state):
    report = state["report"]
    assert report["schema_version"] == "entra.identity-report/v2"
    assert len(report["hypotheses"]) == 7
    assert all(item["status"] == "fresh" for item in report["source_coverage"].values())
    assert all(item["evidence_status"] == "fresh" for item in report["hypotheses"])


@then("the Entra report identifies stale coverage without current hypotheses")
def stale_hypotheses(state):
    report = state["report"]
    assert all(item["reason"] == "stale" for item in report["source_coverage"].values())
    assert report["hypotheses"] == []
    assert all(edge["evidence_status"] == "unknown" for edge in state["graph"].to_dict()["edges"])


def check_oauth_coverage(state, reason):
    report = state["report"]
    assert report["source_coverage"]["oauth_grants"]["status"] == "unknown"
    assert report["source_coverage"]["oauth_grants"]["reason"] == reason
    assert not any(item["category"] == "broad_app_consent" for item in report["hypotheses"])


@then("the Entra report identifies missing OAuth grant coverage without a consent claim")
def missing_coverage(state):
    check_oauth_coverage(state, "not_listed")


@then("the Entra report identifies incomplete OAuth grant coverage without a consent claim")
def incomplete_coverage(state):
    check_oauth_coverage(state, "incomplete")
