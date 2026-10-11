"""Executable acceptance scenarios for the offline AD graph contract."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "plugins/identity-access/ad-assessment-workbench"
sys.path.insert(0, str(PACKAGE))
from adwb import InventoryError, analyze, load_export  # noqa: E402

scenarios("../../specs/features/ad_inventory_and_paths.feature")


@pytest.fixture
def context():
    return {}


@given("the synthetic AD inventory export")
def synthetic_export(context):
    context["export"] = load_export(PACKAGE / "fixtures/synthetic-two-forest.json")


@given("the synthetic AD inventory export with a conflicting identity")
def conflicting_identity(context):
    synthetic_export(context)
    context["export"]["nodes"].append({**copy.deepcopy(context["export"]["nodes"][0]), "kind": "group"})


@given("the synthetic AD inventory export with an unapproved forest edge")
def unapproved_boundary(context):
    synthetic_export(context)
    context["export"]["edges"][2]["kind"] = "privilege"


@when("the AD inventory analyzer runs")
def run_analyzer(context):
    try:
        context["report"] = analyze(context["export"])
    except InventoryError as error:
        context["error"] = error.code


@then("the report contains one candidate path and one missing path")
def candidate_and_missing(context):
    first, second = context["report"]["queries"]
    assert first["status"] == "candidate_paths"
    assert len(first["paths"]) == 1
    assert second["status"] == "not_found_in_collected_graph"


@then("the candidate path requires validation across a protected trust boundary")
def candidate_has_caveats(context):
    path = context["report"]["queries"][0]["paths"][0]
    assert path["status"] == "candidate_requires_validation"
    assert "protected_identity" in path["flags"]
    assert "trust_boundary" in path["flags"]


@then("the missing path is unknown in the collected graph")
def missing_is_unknown(context):
    assert context["report"]["queries"][1]["paths"] == []
    assert context["report"]["coverage"]["hosts"]["host-b"] == "unknown"


@then("the AD inventory analyzer rejects the export")
def rejected(context):
    assert context.get("error") in {"conflicting_identity", "unapproved_forest_boundary"}
