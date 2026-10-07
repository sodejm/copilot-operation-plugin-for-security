"""Executable acceptance scenarios for execution authorization and legacy receipt rejection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.contracts.models import ActionPlan, Engagement
from cops.execution.authorization import (
    AuthorizationError,
    AuthorizationSigner,
    AuthorizationTrustStore,
    LegacyReceiptDeprecationWarning,
    TrustedAuthorizationKey,
    consume_execution_authorization,
    create_execution_authorization,
    verify_execution_authorization,
)
from tests.auth_testkit import make_test_authorization_context

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
    base_signer, _, base_engagement = make_test_authorization_context(auth_context["plan"])
    engagement_doc = base_engagement.to_dict()
    engagement_doc["operator"] = operator
    signer = AuthorizationSigner(key_id=base_signer.key_id, operator=operator, secret=base_signer.secret)
    auth_context.update(
        signer=signer,
        engagement=Engagement.from_dict(engagement_doc),
        trust_store=AuthorizationTrustStore([
            TrustedAuthorizationKey(key_id=signer.key_id, operator=operator, secret=signer.secret)
        ]),
    )
    auth = create_execution_authorization(
        auth_context["plan"],
        signer=auth_context["signer"],
        engagement=auth_context["engagement"],
        worker_identity="worker-node-01",
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
        trust_store=auth_context["trust_store"],
        engagement=auth_context["engagement"],
        worker_identity="worker-node-01",
    )
    assert verified.authorization_id == auth_context["authorization"].authorization_id


@given("an execution authorization envelope created for that plan")
def create_auth_for_plan(auth_context):
    create_auth_envelope(auth_context, "secops@corp.internal")


@when("the action plan target or operations are altered")
def alter_action_plan(auth_context):
    original = auth_context["plan"]
    snapshot = original.approved_snapshot()
    snapshot.pop("schema_version")
    snapshot["target"] = "10.200.0.99"
    altered = ActionPlan.create(**snapshot)
    auth_context["altered_plan"] = altered


@then("verification of the authorization is rejected with an integrity mismatch")
def verify_rejected_integrity(auth_context):
    with pytest.raises(AuthorizationError, match="does not bind the requested action plan"):
        verify_execution_authorization(
            auth_context["authorization"],
            auth_context["altered_plan"],
            trust_store=auth_context["trust_store"],
            engagement=auth_context["engagement"],
            worker_identity="worker-node-01",
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
        with pytest.raises(AuthorizationError, match="legacy authorization receipts cannot authorize execution"):
            _, trust_store, engagement = make_test_authorization_context(auth_context["target_plan"])
            verify_execution_authorization(
                auth_context["legacy_receipt"],
                auth_context["target_plan"],
                trust_store=trust_store,
                engagement=engagement,
                worker_identity="worker-node-01",
            )


@given("a verified execution authorization envelope")
def load_verified_envelope(auth_context):
    plan_data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    plan = ActionPlan.from_dict(plan_data)
    auth_context["plan"] = plan
    create_auth_envelope(auth_context, "secops@corp.internal")
    verified = verify_execution_authorization(
        auth_context["authorization"],
        plan,
        trust_store=auth_context["trust_store"],
        engagement=auth_context["engagement"],
        worker_identity="worker-node-01",
    )
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
