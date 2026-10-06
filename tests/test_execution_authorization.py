"""Comprehensive tests for COPS descriptor-bound execution authorization."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan, ExecutionAuthorization
from cops.contracts.validation import validate_contract
from cops.execution import (
    AuthorizationDeniedError,
    AuthorizationError,
    LegacyReceiptDeprecationWarning,
    compute_authorization_signature,
    consume_execution_authorization,
    create_execution_authorization,
    request_interactive_plan_authorization,
    verify_execution_authorization,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"


@pytest.fixture
def valid_action_plan() -> ActionPlan:
    data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    return ActionPlan.from_dict(data)


@pytest.fixture
def valid_execution_auth() -> ExecutionAuthorization:
    data = json.loads((FIXTURES / "valid_execution_authorization.json").read_text(encoding="utf-8"))
    return ExecutionAuthorization.from_dict(data)


def test_create_execution_authorization_success(valid_action_plan):
    """Test generating a valid authorization envelope bound to an ActionPlan."""
    auth = create_execution_authorization(
        valid_action_plan,
        operator="secops-operator@corp.internal",
        valid_hours=4,
        worker_identity="worker-01",
    )
    assert auth.schema_version == "cops.execution-authorization/v1"
    assert auth.status == "approved"
    assert auth.action_plan_id == valid_action_plan.plan_id
    assert auth.plan_digest == valid_action_plan.plan_digest
    assert auth.operator == "secops-operator@corp.internal"
    assert auth.bound_parameters["worker_identity"] == "worker-01"

    # Verify document validates via schema validator
    doc = auth.to_dict()
    validated = validate_contract(doc, "execution_authorization")
    assert validated["authorization_id"] == auth.authorization_id


def test_verify_execution_authorization_success(valid_action_plan, valid_execution_auth):
    """Test verifying a matching authorization envelope."""
    verified = verify_execution_authorization(
        valid_execution_auth,
        valid_action_plan,
        current_time_iso="2026-10-02T12:00:00Z",
    )
    assert verified.authorization_id == valid_execution_auth.authorization_id


def test_reject_tampered_signature_digest(valid_action_plan, valid_execution_auth):
    """Test that modifying signature_digest causes verification failure."""
    tampered_dict = valid_execution_auth.to_dict()
    tampered_dict["signature_digest"] = "a" * 64

    with pytest.raises(AuthorizationError, match="signature_digest mismatch|signature digest mismatch"):
        verify_execution_authorization(
            tampered_dict,
            valid_action_plan,
            current_time_iso="2026-10-02T12:00:00Z",
        )


def test_reject_plan_digest_tamper_after_authorization(valid_action_plan, valid_execution_auth):
    """Test that altering action plan operations or targets after authorization is rejected."""
    # Tamper with the action plan
    plan_dict = valid_action_plan.to_dict()
    plan_dict["target"] = "192.168.1.1"  # changed target
    # plan_digest in plan_dict is now mismatched with the actual parameters or we rebuild it
    tampered_plan = ActionPlan.create(
        plan_id=valid_action_plan.plan_id,
        engagement_id=valid_action_plan.engagement_id,
        scenario_id=valid_action_plan.scenario_id,
        target="192.168.1.1",
        specialist_id=valid_action_plan.specialist_id,
        operations=valid_action_plan.operations,
        limits=valid_action_plan.limits,
        credential_references=valid_action_plan.credential_references,
        created_at=valid_action_plan.created_at,
    )

    with pytest.raises(AuthorizationError, match="action plan digest mismatch"):
        verify_execution_authorization(
            valid_execution_auth,
            tampered_plan,
            current_time_iso="2026-10-02T12:00:00Z",
        )


def test_reject_action_plan_id_mismatch(valid_action_plan, valid_execution_auth):
    """Test that authorization for plan A cannot be used on plan B."""
    plan_dict = valid_action_plan.to_dict()
    plan_dict["plan_id"] = "plan-different-id"
    different_plan = ActionPlan.from_dict(plan_dict)

    with pytest.raises(AuthorizationError, match="authorization bound to plan"):
        verify_execution_authorization(
            valid_execution_auth,
            different_plan,
            current_time_iso="2026-10-02T12:00:00Z",
        )


def test_reject_engagement_mismatch(valid_action_plan, valid_execution_auth):
    """Test that engagement scope mismatch is rejected."""
    auth_dict = valid_execution_auth.to_dict()
    auth_dict["engagement_id"] = "eng-unauthorized-target"
    # recompute signature so signature is valid, but engagement is mismatched with plan
    auth_dict["signature_digest"] = compute_authorization_signature(
        action_plan_id=auth_dict["action_plan_id"],
        plan_digest=auth_dict["plan_digest"],
        engagement_id=auth_dict["engagement_id"],
        operator=auth_dict["operator"],
        issued_at=auth_dict["issued_at"],
        authorized_until_utc=auth_dict["authorized_until_utc"],
        bound_parameters=auth_dict["bound_parameters"],
        approval_mode=auth_dict["approval_mode"],
    )

    with pytest.raises(AuthorizationError, match="engagement ID mismatch"):
        verify_execution_authorization(
            auth_dict,
            valid_action_plan,
            current_time_iso="2026-10-02T12:00:00Z",
        )


def test_reject_worker_identity_mismatch(valid_action_plan):
    """Test that worker identity bound in envelope must match executing worker."""
    auth = create_execution_authorization(
        valid_action_plan,
        operator="op@corp",
        valid_hours=1,
        worker_identity="worker-alpha",
    )

    # Missing worker
    with pytest.raises(AuthorizationError, match="requires worker_identity"):
        verify_execution_authorization(
            auth,
            valid_action_plan,
            worker_identity=None,
            current_time_iso=auth.issued_at,
        )

    # Wrong worker
    with pytest.raises(AuthorizationError, match="worker identity mismatch"):
        verify_execution_authorization(
            auth,
            valid_action_plan,
            worker_identity="worker-beta",
            current_time_iso=auth.issued_at,
        )

    # Matching worker
    verified = verify_execution_authorization(
        auth,
        valid_action_plan,
        worker_identity="worker-alpha",
        current_time_iso=auth.issued_at,
    )
    assert verified.authorization_id == auth.authorization_id


def test_reject_expired_authorization(valid_action_plan, valid_execution_auth):
    """Test that expired envelope fails verification."""
    with pytest.raises(AuthorizationError, match="execution authorization expired"):
        verify_execution_authorization(
            valid_execution_auth,
            valid_action_plan,
            current_time_iso="2026-10-05T00:00:00Z",
        )


def test_reject_consumed_or_revoked_authorization(valid_action_plan, valid_execution_auth):
    """Test that non-approved state fails verification."""
    auth_dict = valid_execution_auth.to_dict()
    auth_dict["status"] = "consumed"

    with pytest.raises(AuthorizationError, match="not in approved state"):
        verify_execution_authorization(
            auth_dict,
            valid_action_plan,
            current_time_iso="2026-10-02T12:00:00Z",
        )


def test_atomic_consumption_and_replay_prevention(valid_action_plan, valid_execution_auth):
    """Test that an authorization envelope can be consumed once and cannot be replayed."""
    verified = verify_execution_authorization(
        valid_execution_auth,
        valid_action_plan,
        current_time_iso="2026-10-02T12:00:00Z",
    )
    consumed = consume_execution_authorization(
        verified,
        worker_identity="worker-linux-01",
        consumed_at="2026-10-02T12:05:00Z",
    )
    assert consumed.status == "consumed"
    assert consumed.consumed_by_worker == "worker-linux-01"

    # Replay attempt
    with pytest.raises(AuthorizationError, match="cannot consume authorization in 'consumed' state"):
        consume_execution_authorization(consumed, worker_identity="worker-linux-01")


def test_reject_legacy_receipt_as_execution_authority(valid_action_plan):
    """Test that legacy receipts (1.0) emit deprecation warning and are rejected for execution."""
    legacy_receipt = {
        "schema_version": "1.0",
        "receipt_id": "rcpt-1234567890123456",
        "timestamp_utc": "2026-10-02T10:00:00Z",
        "operator": "op",
        "specialist_id": "cops-network-specialist",
        "action_type": "port_scan",
        "target_scope": ["10.0.0.5"],
        "allowed_operations": ["scan"],
        "authorized_until_utc": "2026-10-02T14:00:00Z",
        "approval_mode": "interactive_confirmation",
        "verification_hash": "a" * 64,
    }

    with pytest.warns(LegacyReceiptDeprecationWarning, match="Legacy unkeyed authorization receipts"):
        with pytest.raises(AuthorizationError, match="legacy authorization receipts .* cannot authorize new execution"):
            verify_execution_authorization(legacy_receipt, valid_action_plan)


def test_interactive_plan_authorization_approved(valid_action_plan):
    """Test interactive plan authorization with operator approval."""
    buf = io.StringIO()
    auth = request_interactive_plan_authorization(
        valid_action_plan,
        valid_hours=2,
        worker_identity="worker-local",
        input_func=lambda _: "APPROVE",
        output_stream=buf,
    )
    assert isinstance(auth, ExecutionAuthorization)
    assert auth.status == "approved"
    assert auth.action_plan_id == valid_action_plan.plan_id
    assert "Execution Authorization granted" in buf.getvalue()


def test_interactive_plan_authorization_denied(valid_action_plan):
    """Test interactive plan authorization aborted by operator."""
    buf = io.StringIO()
    with pytest.raises(AuthorizationDeniedError, match="aborted by operator"):
        request_interactive_plan_authorization(
            valid_action_plan,
            input_func=lambda _: "abort",
            output_stream=buf,
        )
