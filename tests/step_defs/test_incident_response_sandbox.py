"""Executable acceptance scenarios for fixture-only incident actions."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

PACKAGE = Path(__file__).resolve().parents[2] / "plugins/incident-response/incident-response-sandbox"
sys.path.insert(0, str(PACKAGE))
from incident_response.core import ActionError, build_plan, dry_run, execute  # noqa: E402

scenarios("../../specs/features/incident_response_sandbox.feature")


@pytest.fixture
def context():
    return {}


def setup(context):
    context["fixture"] = {"schema": "cops.ir-fixture/v1", "tenant": "example", "revision": 0,
                          "permissions": ["isolate-host"], "throttled": False,
                          "failure_mode": "none", "targets": {
                              "host-1": {"action": "isolate-host", "state": "active"},
                              "host-2": {"action": "isolate-host", "state": "active"}},
                          "executions": []}
    context["plan"] = build_plan(action="isolate-host", tenant="example", target="host-1",
                                 expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                                 nonce="acceptance-1", approver_assertion="analyst")


@given("a synthetic tenant fixture and a matching expiring plan")
def matching(context):
    setup(context)


@given("a successful dry run receipt")
def receipt(context):
    setup(context)
    context["receipt"] = dry_run(context["plan"], context["fixture"])


@given("a fixture configured for partial action failure")
def partial(context):
    setup(context)
    context["fixture"]["failure_mode"] = "partial"


@when("the analyst dry runs and executes the plan")
def run(context):
    receipt = dry_run(context["plan"], context["fixture"])
    context["updated"], context["result"] = execute(context["plan"], receipt, context["fixture"])


@when("the fixture changes before execution")
def changed(context):
    context["fixture"]["targets"]["host-1"]["state"] = "isolated"
    with pytest.raises(ActionError, match="drift"):
        execute(context["plan"], context["receipt"], context["fixture"])


@when("the analyst executes a dry run plan")
def run_partial(context):
    context["updated"], context["result"] = execute(
        context["plan"], dry_run(context["plan"], context["fixture"]), context["fixture"])


@then("only the named fixture target changes")
def named(context):
    assert context["updated"]["targets"]["host-1"]["state"] == "isolated"
    assert context["updated"]["targets"]["host-2"]["state"] == "active"


@then("a replay of the same plan is rejected")
def replay(context):
    with pytest.raises(ActionError):
        dry_run(context["plan"], context["updated"])


@then("execution rejects the drift without applying the action")
def no_apply(context):
    assert context["fixture"]["revision"] == 0
    assert context["fixture"]["executions"] == []


@then("the result records partial success and rollback outcome")
def rollback(context):
    assert context["result"]["outcome"] == "partial-rolled-back"
    assert context["updated"]["targets"]["host-1"]["state"] == "active"
