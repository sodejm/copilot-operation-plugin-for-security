"""Tests for authenticated execution authorization and lifecycle handling."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan, ExecutionAuthorization
from cops.contracts.validation import validate_contract
from cops.execution.authorization import (
    AuthorizationDeniedError,
    AuthorizationError,
    AuthorizationTrustStore,
    LegacyReceiptDeprecationWarning,
    TrustedAuthorizationKey,
    compute_authorization_signature,
    consume_execution_authorization,
    create_execution_authorization,
    request_interactive_plan_authorization,
    verify_execution_authorization,
)
from tests.auth_testkit import make_test_authorization_context

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"
ISSUED_AT = "2026-10-02T10:00:00Z"
EXPIRES_AT = "2026-10-02T14:00:00Z"
WORKER = "worker-01"


@pytest.fixture
def valid_action_plan() -> ActionPlan:
    data = json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8"))
    return ActionPlan.from_dict(data)


@pytest.fixture
def auth_context(valid_action_plan):
    return make_test_authorization_context(valid_action_plan)


@pytest.fixture
def valid_execution_auth(valid_action_plan, auth_context) -> ExecutionAuthorization:
    signer, _, engagement = auth_context
    return create_execution_authorization(
        valid_action_plan,
        signer=signer,
        engagement=engagement,
        worker_identity=WORKER,
        issued_at=ISSUED_AT,
        authorized_until_utc=EXPIRES_AT,
    )


def verify(authorization, plan, auth_context, **overrides):
    _, trust_store, engagement = auth_context
    parameters = {
        "trust_store": trust_store,
        "engagement": engagement,
        "worker_identity": WORKER,
        "current_time_iso": "2026-10-02T12:00:00Z",
    }
    parameters.update(overrides)
    return verify_execution_authorization(authorization, plan, **parameters)


def altered_plan(plan, **changes):
    snapshot = plan.approved_snapshot()
    snapshot.pop("schema_version")
    snapshot.update(changes)
    return ActionPlan.create(**snapshot)


def test_create_execution_authorization_success(valid_action_plan, valid_execution_auth, auth_context):
    signer, _, _ = auth_context
    auth = valid_execution_auth
    assert auth.schema_version == "cops.execution-authorization/v1"
    assert auth.status == "approved"
    assert auth.action_plan_id == valid_action_plan.plan_id
    assert auth.plan_digest == valid_action_plan.plan_digest
    assert auth.operator == signer.operator
    assert auth.signing_key_id == signer.key_id
    assert auth.signature_algorithm == "hmac-sha256"
    assert auth.bound_parameters["worker_identity"] == WORKER
    validated = validate_contract(auth.to_dict(), "execution_authorization")
    assert validated["authorization_id"] == auth.authorization_id


def test_trust_store_rejects_unprotected_files_and_active_keys_without_windows(tmp_path):
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(
        json.dumps(
            {
                "schema_version": "cops.authorization-trust-store/v1",
                "keys": [
                    {
                        "key_id": "test-key",
                        "operator_identity": "secops-lead",
                        "algorithm": "hmac-sha256",
                        "secret_env": "COPS_TEST_SECRET",
                        "valid_from_utc": "2026-01-01T00:00:00Z",
                        "valid_until_utc": "2030-01-01T00:00:00Z",
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    trust_path.chmod(0o644)
    with pytest.raises(AuthorizationError, match="permissions"):
        AuthorizationTrustStore.from_file(trust_path, environ={"COPS_TEST_SECRET": "x" * 32})

    trust_path.chmod(0o600)
    link = tmp_path / "trust-link.json"
    link.symlink_to(trust_path)
    with pytest.raises(AuthorizationError, match="symbolic link"):
        AuthorizationTrustStore.from_file(link, environ={"COPS_TEST_SECRET": "x" * 32})

    document = json.loads(trust_path.read_text(encoding="utf-8"))
    document["keys"][0].pop("valid_from_utc")
    trust_path.write_text(json.dumps(document), encoding="utf-8")
    trust_path.chmod(0o600)
    with pytest.raises(AuthorizationError, match="validity windows"):
        AuthorizationTrustStore.from_file(trust_path, environ={"COPS_TEST_SECRET": "x" * 32})

    with pytest.raises(AuthorizationError, match="validity windows"):
        TrustedAuthorizationKey(
            key_id="unbounded",
            operator="secops-lead",
            secret=b"x" * 32,
        )


def test_revoked_trust_key_loads_without_secret_material(tmp_path):
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(
        json.dumps(
            {
                "schema_version": "cops.authorization-trust-store/v1",
                "keys": [
                    {
                        "key_id": "retired-key",
                        "operator_identity": "secops-lead",
                        "algorithm": "hmac-sha256",
                        "valid_from_utc": "2026-01-01T00:00:00Z",
                        "valid_until_utc": "2030-01-01T00:00:00Z",
                        "status": "revoked",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    trust_path.chmod(0o600)
    trust_store = AuthorizationTrustStore.from_file(trust_path, environ={})
    with pytest.raises(AuthorizationError, match="revoked"):
        trust_store.resolve(
            "retired-key",
            "secops-lead",
            ISSUED_AT,
            EXPIRES_AT,
        )


def test_execution_authorization_fixtures_use_authenticated_envelope_shape(valid_action_plan, auth_context):
    valid = json.loads((FIXTURES / "valid_execution_authorization.json").read_text(encoding="utf-8"))
    tampered = json.loads(
        (FIXTURES / "invalid_execution_authorization_tampered.json").read_text(encoding="utf-8")
    )
    validate_contract(valid, "execution_authorization")
    validate_contract(tampered, "execution_authorization")
    assert set(valid["bound_parameters"]) == {"action_plan", "worker_identity"}
    assert {"signature_algorithm", "signing_key_id"} <= valid.keys()
    with pytest.raises(AuthorizationError):
        verify(tampered, valid_action_plan, auth_context)


def test_verify_execution_authorization_success(valid_action_plan, valid_execution_auth, auth_context):
    verified = verify(valid_execution_auth, valid_action_plan, auth_context)
    assert verified.authorization_id == valid_execution_auth.authorization_id


def test_reject_tampered_signature_digest(valid_action_plan, valid_execution_auth, auth_context):
    tampered = valid_execution_auth.to_dict()
    tampered["signature_digest"] = "a" * 64
    with pytest.raises(AuthorizationError, match="signature verification failed"):
        verify(tampered, valid_action_plan, auth_context)


def test_reject_plan_digest_tamper_after_authorization(valid_action_plan, valid_execution_auth, auth_context):
    tampered = altered_plan(valid_action_plan, target="192.168.1.1")
    with pytest.raises(AuthorizationError, match="does not bind the requested action plan"):
        verify(valid_execution_auth, tampered, auth_context)


def test_reject_action_plan_id_mismatch(valid_action_plan, valid_execution_auth, auth_context):
    different = altered_plan(valid_action_plan, plan_id="plan-different-id")
    with pytest.raises(AuthorizationError, match="does not bind the requested action plan"):
        verify(valid_execution_auth, different, auth_context)


def test_reject_engagement_mismatch(valid_action_plan, valid_execution_auth, auth_context):
    signer, _, _ = auth_context
    mismatched = valid_execution_auth.to_dict()
    mismatched["engagement_id"] = "eng-unauthorized-target"
    payload = valid_execution_auth.signed_payload()
    payload["engagement_id"] = mismatched["engagement_id"]
    mismatched["signature_digest"] = compute_authorization_signature(payload, secret=signer.secret)
    with pytest.raises(AuthorizationError, match="does not bind the requested action plan"):
        verify(mismatched, valid_action_plan, auth_context)


@pytest.mark.parametrize("worker_identity", [None, "worker-beta"])
def test_reject_worker_identity_mismatch(valid_action_plan, valid_execution_auth, auth_context, worker_identity):
    with pytest.raises(AuthorizationError, match="worker identity does not match"):
        verify(valid_execution_auth, valid_action_plan, auth_context, worker_identity=worker_identity)


def test_reject_expired_authorization(valid_action_plan, valid_execution_auth, auth_context):
    with pytest.raises(AuthorizationError, match="not currently valid"):
        verify(valid_execution_auth, valid_action_plan, auth_context, current_time_iso="2026-10-05T00:00:00Z")


@pytest.mark.parametrize("status", ["consumed", "revoked"])
def test_reject_consumed_or_revoked_authorization(valid_action_plan, valid_execution_auth, auth_context, status):
    authorization = valid_execution_auth.to_dict()
    authorization["status"] = status
    if status == "consumed":
        authorization["consumed_at"] = "2026-10-02T11:00:00Z"
        authorization["consumed_by_worker"] = WORKER
    with pytest.raises(AuthorizationError, match="not approved"):
        verify(authorization, valid_action_plan, auth_context)


def test_consumption_lifecycle_rejects_replay(valid_action_plan, valid_execution_auth, auth_context):
    verified = verify(valid_execution_auth, valid_action_plan, auth_context)
    consumed = consume_execution_authorization(
        verified, worker_identity=WORKER, consumed_at="2026-10-02T12:05:00Z"
    )
    assert consumed.status == "consumed"
    assert consumed.consumed_by_worker == WORKER
    with pytest.raises(AuthorizationError, match="cannot consume authorization in 'consumed' state"):
        consume_execution_authorization(consumed, worker_identity=WORKER)


def test_reject_legacy_receipt_as_execution_authority(valid_action_plan, auth_context):
    legacy_receipt = {
        "schema_version": "1.0",
        "receipt_id": "rcpt-1234567890123456",
        "timestamp_utc": ISSUED_AT,
        "operator": "op",
        "specialist_id": "cops-network-specialist",
        "action_type": "port_scan",
        "target_scope": ["10.0.0.5"],
        "allowed_operations": ["scan"],
        "authorized_until_utc": EXPIRES_AT,
        "approval_mode": "interactive_confirmation",
        "verification_hash": "a" * 64,
    }
    with pytest.warns(LegacyReceiptDeprecationWarning, match="legacy unkeyed authorization receipts"):
        with pytest.raises(AuthorizationError, match="legacy authorization receipts cannot authorize execution"):
            verify(legacy_receipt, valid_action_plan, auth_context)


def test_interactive_plan_authorization_approved(valid_action_plan, auth_context):
    signer, _, engagement = auth_context
    output = io.StringIO()
    auth = request_interactive_plan_authorization(
        valid_action_plan,
        signer=signer,
        engagement=engagement,
        worker_identity=WORKER,
        valid_hours=2,
        input_func=lambda _: "APPROVE",
        output_stream=output,
    )
    assert isinstance(auth, ExecutionAuthorization)
    assert auth.status == "approved"
    assert auth.action_plan_id == valid_action_plan.plan_id
    assert valid_action_plan.plan_digest in output.getvalue()
    verify(auth, valid_action_plan, auth_context, current_time_iso=auth.issued_at)


def test_interactive_plan_authorization_denied(valid_action_plan, auth_context):
    signer, _, engagement = auth_context
    with pytest.raises(AuthorizationDeniedError, match="was denied"):
        request_interactive_plan_authorization(
            valid_action_plan,
            signer=signer,
            engagement=engagement,
            worker_identity=WORKER,
            input_func=lambda _: "abort",
            output_stream=io.StringIO(),
        )
