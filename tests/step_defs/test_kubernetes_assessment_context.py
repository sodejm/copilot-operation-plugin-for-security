"""Executable acceptance scenarios for Kubernetes context reconciliation."""

from __future__ import annotations

import copy
import json
import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "plugins/offensive-security/kubernetes-assessment-workbench"
sys.path.insert(0, str(PACKAGE))
from kubernetes_assessment_context.core import GateError, assess  # noqa: E402

scenarios("../../specs/features/kubernetes_assessment_context.feature")


@pytest.fixture
def context():
    fixture = PACKAGE / "fixtures/synthetic/context.json"
    return {"record": json.loads(fixture.read_text(encoding="utf-8"))}


@given("a synthetic approved Kubernetes assessment record")
def approved_record(context):
    assert context["record"]["plan"]["approval_reference"] == "SYNTHETIC-K8S-ROE-121"


@when("the observed context switches to another cluster")
def switch_context(context):
    record = context["record"]
    record["observation"]["current_context"] = {"name": "other", "cluster": "other-cluster", "user": "reader"}
    record["observation"]["contexts"].append(copy.deepcopy(record["observation"]["current_context"]))


@then("the importer rejects the context switch")
def reject_switch(context):
    with pytest.raises(GateError, match="context_mismatch"):
        assess(context["record"])


@when("another context reuses the selected display name")
def duplicate_name(context):
    context["record"]["observation"]["contexts"].append(
        {"name": "lab-east", "cluster": "other-cluster", "user": "reader"}
    )


@then("the importer rejects the duplicate name")
def reject_duplicate(context):
    with pytest.raises(GateError, match="duplicate_context_name"):
        assess(context["record"])


@when("the observed identity anchor is absent")
def missing_anchor(context):
    del context["record"]["observation"]["identity_anchor"]
    context["report"] = assess(context["record"])


@then("the report records unresolved identity and blocks live execution")
def unresolved(context):
    report = context["report"]
    assert report["cluster_identity"]["status"] == "unresolved"
    assert "stable_identity_unresolved" in report["blockers"]
    assert report["live_execution_ready"] is False


@when("an approved namespace is denied and another is unapproved")
def deny_namespace(context):
    observation = context["record"]["observation"]
    observation["namespace_access"] = [
        {"namespace": "payments", "status": "denied"},
        {"namespace": "unapproved", "status": "accessible"},
    ]
    context["report"] = assess(context["record"])


@then("only approved namespaces appear and denial is visible")
def scope_and_denial(context):
    assert context["report"]["namespaces"] == [{"namespace": "payments", "status": "denied"}]
    assert "namespace_access_incomplete" in context["report"]["blockers"]


@when("managed control-plane and node access are unavailable")
def access_limits(context):
    facts = context["record"]["observation"]["cluster_facts"]
    facts["control_plane_access"] = "managed_unavailable"
    facts["node_access"] = "unavailable"
    context["report"] = assess(context["record"])


@then("the report records access limits without security conclusions")
def visible_limits(context):
    facts = context["report"]["cluster_facts"]
    assert facts["control_plane_access"] == "managed_unavailable"
    assert facts["node_access"] == "unavailable"
    assert "control_plane_unavailable" in context["report"]["limitations"]
    assert "node_access_unavailable" in context["report"]["limitations"]
    assert "secure" not in json.dumps(context["report"]).lower()


@when("the record is assessed with network disabled")
def offline(context):
    with (
        patch.object(socket, "socket", side_effect=AssertionError("network attempted")),
        patch.object(socket, "create_connection", side_effect=AssertionError("network attempted")),
    ):
        context["report"] = assess(context["record"])


@then("the offline report is produced with no network requests")
def no_network(context):
    assert context["report"]["network_requests"] == 0
    assert context["report"]["cluster_identity"]["status"] == "matched_sanitized_export"
