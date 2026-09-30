"""Executable acceptance scenarios for offline attack surface planning."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import socket
import sys
from unittest.mock import patch

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "plugins/offensive-security/attack-surface-planner"
FIXTURE = PACKAGE / "fixtures/synthetic"
sys.path.insert(0, str(PACKAGE))
from attack_surface_planner.core import GateError, analyze, canonical  # noqa: E402

scenarios("../../specs/features/attack_surface_planner.feature")


@pytest.fixture
def context(tmp_path):
    target = tmp_path / "fixture"
    shutil.copytree(FIXTURE, target)
    return {"manifest": target / "scope.json"}


@given("a synthetic signed-off scope and four pinned local exports")
def synthetic_scope(context):
    manifest = json.loads(context["manifest"].read_text())
    assert len(manifest["sources"]) == 4
    assert manifest["approval"]["reference"] == "SYNTHETIC-ROE-001"


@when("an active mode or mismatched source hash is supplied")
def invalid_inputs(context):
    path = context["manifest"]
    manifest = json.loads(path.read_text())
    manifest["mode"] = "active"
    path.write_text(json.dumps(manifest))
    with pytest.raises(GateError, match="offline mode"):
        analyze(path)
    manifest["mode"] = "offline"
    manifest["sources"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(manifest))
    context["invalid_manifest"] = path


@then("the planner fails before producing a test plan")
def no_plan(context):
    with pytest.raises(GateError, match="SHA-256 mismatch"):
        analyze(context["invalid_manifest"])


@when("the offline surface plan is generated")
def generate(context):
    context["report"] = analyze(context["manifest"])


@then("every discovery retains source hash pointer time and confidence")
def provenance(context):
    report = context["report"]
    source_hashes = {source["sha256"] for source in report["sources"]}
    for item in report["surface_map"]:
        evidence = item["evidence"]
        assert evidence["source_sha256"] in source_hashes
        assert evidence["pointer"].startswith("/records/")
        assert evidence["collected_at"].endswith("Z")
        assert evidence["confidence"] == "reported-export"


@then("outside discoveries are excluded and ambiguous discoveries are unresolved")
def scope_decisions(context):
    report = context["report"]
    assert report["summary"] == {"in_scope": 4, "excluded": 3, "unresolved": 1}
    targeted = {item["asset_id"] for item in report["test_plan"]}
    assert targeted == {item["asset_id"] for item in report["surface_map"]
                        if item["decision"] == "in_scope"}


@when("the offline surface plan is generated twice")
def generate_twice(context):
    context["first"] = canonical(analyze(context["manifest"]))
    context["second"] = canonical(analyze(context["manifest"]))


@then("the plans match and every proposal has permission telemetry stop and cleanup")
def complete_proposals(context):
    assert context["first"] == context["second"]
    report = json.loads(context["first"])
    for item in report["test_plan"]:
        assert item["authorization"]["reference"]
        assert item["authorization"]["allowed_method"] == "passive-review"
        assert item["expected_telemetry"] and item["stop_condition"] and item["cleanup"]


@when("the offline surface plan is generated with network disabled")
def network_disabled(context):
    with patch.object(socket, "socket", side_effect=AssertionError("network attempted")), \
         patch.object(socket, "create_connection", side_effect=AssertionError("network attempted")):
        context["report"] = analyze(context["manifest"])


@then("the plan succeeds without network activity")
def no_network(context):
    assert context["report"]["network_requests"] == 0
    assert len(context["report"]["test_plan"]) == 4
