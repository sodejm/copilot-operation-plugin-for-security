"""Executable acceptance scenarios for execution authorization and legacy receipt rejection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.contracts.models import ActionPlan
from cops.execution import (
    AuthorizationError,
    LegacyReceiptDeprecationWarning,
    consume_execution_authorization,
    create_execution_authorization,
    verify_execution_authorization,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"

scenarios("../../specs/features/execution_authorization.feature")


@pytest.fixture
def auth_context():
    return {}


@given(parsers.parse('a valid action plan from "{filename}"'))
def load_valid_plan(auth_context, filename):
    data = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
    auth_context["plan"] = ActionPlan.from_dict(data)


@when(parsers.parse('an execution authorization envelope is created by operator "{operator}"'))
def create_auth_envelope(auth_context, operator):
    auth = create_execution_authorization(
        auth_context["plan"],
        operator=operator,
        valid_hours=4,
    )
    auth_context["authorization"] = auth


@then(parsers.parse('the authorization status is "{expected_status}"'))
def verify_status(auth_context, expected_status):
    assert auth_context["authorization"].status == expected_status


@then("verification against the action plan succeeds")
def verify_success(auth_context):
    verified = verify_execution_authorization(
        auth_context["authorization"],
        auth_context["plan"],
    )
    assert verified.authorization_id == auth_context["authorization"].authorization_id


@given("an execution authorization envelope created for that plan")
def create_auth_for_plan(auth_context):
    auth_context["authorization"] = create_execution_authorization(
        auth_context["plan"],
        operator="secops@corp.internal",
        valid_hours=4,
    )


@when("the action plan target or operations are altered")
def alter_action_plan(auth_context):
    original = auth_context["plan"]
    # create new plan with altered target
    altered = ActionPlan.create(
        plan_id=original.plan_id,
        engagement_id=original.engagement_id,
        scenario_id=original.scenario_id,
        target="10.200.0.99",
        specialist_id=original.specialist_id,
        operations=original.operations,
        limits=original.limits,
        credential_references=original.credential_references,
        created_at=original.created_at,
    )
    auth_context["altered_plan"] = altered


@then("verification of the authorization is rejected with an integrity mismatch")
def verify_rejected_integrity(auth_context):
    with pytest.raises(AuthorizationError, match="action plan digest mismatch"):
        verify_execution_authorization(
            auth_context["authorization"],
            auth_context["altered_plan"],
        )


@given(parsers.parse('a legacy authorization receipt with schema version "{version}"'))
def load_legacy_receipt(auth_context, version):
    auth_context["legacy_receipt"] = {
        "schema_version": version,
        "receipt_id": "rcpt-1234567890123456",
        "timestamp_utc": "2026-10-02T10:00:00Z",
        "operator": "legacy-operator",
        "specialist_id": "cops-network-specialist",
        "action_type": "port_scan",
        "target_scope": ["10.0.0.5"],
        "allowed_operations": ["scan"],
        "authorized_until_utc": "2026-10-02T14:00:00Z",
        "approval_mode": "interactive_confirmation",
        "verification_hash": "0" * 64,
    }


@when("attempting to verify the legacy receipt as execution authority for an action plan")
def attempt_verify_legacy(auth_context):
    plan_data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    auth_context["target_plan"] = ActionPlan.from_dict(plan_data)


@then("verification is rejected with a deprecation warning and authorization failure")
def verify_legacy_rejected(auth_context):
    with pytest.warns(LegacyReceiptDeprecationWarning):
        with pytest.raises(AuthorizationError, match="legacy authorization receipts .* cannot authorize new execution"):
            verify_execution_authorization(
                auth_context["legacy_receipt"],
                auth_context["target_plan"],
            )


@given("a verified execution authorization envelope")
def load_verified_envelope(auth_context):
    plan_data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan = ActionPlan.from_dict(plan_data)
    auth = create_execution_authorization(
        plan,
        operator="secops@corp.internal",
        valid_hours=4,
    )
    verified = verify_execution_authorization(auth, plan)
    auth_context["verified_auth"] = verified


@when(parsers.parse('the authorization envelope is consumed by worker "{worker}"'))
def consume_envelope(auth_context, worker):
    auth_context["consumed_auth"] = consume_execution_authorization(
        auth_context["verified_auth"],
        worker_identity=worker,
    )


@then(parsers.parse('the authorization status transitions to "{expected_status}"'))
def verify_consumed_status(auth_context, expected_status):
    assert auth_context["consumed_auth"].status == expected_status


@then("attempting to consume the authorization again is rejected")
def verify_replay_rejected(auth_context):
    with pytest.raises(AuthorizationError, match="cannot consume authorization in 'consumed' state"):
        consume_execution_authorization(
            auth_context["consumed_auth"],
            worker_identity="worker-node-02",
        )
