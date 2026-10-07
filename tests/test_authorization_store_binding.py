"""Regression tests binding atomic consumption to the verified approval receipt."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan
from cops.execution.authorization import (
    create_execution_authorization,
    verify_execution_authorization,
)
from cops.execution.store import ApprovalStore, ApprovalStoreConflictError
from tests.auth_testkit import make_test_authorization_context

ISSUED_AT = "2026-10-02T10:00:00Z"
EXPIRES_AT = "2026-10-02T14:00:00Z"
NOW = "2026-10-02T12:00:00Z"
WORKER = "worker-01"


@pytest.fixture
def approval_context(tmp_path):
    fixture = Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json"
    plan = ActionPlan.from_dict(json.loads(fixture.read_text(encoding="utf-8")))
    signer, trust_store, engagement = make_test_authorization_context(plan)
    authorization = create_execution_authorization(
        plan,
        signer=signer,
        engagement=engagement,
        worker_identity=WORKER,
        issued_at=ISSUED_AT,
        authorized_until_utc=EXPIRES_AT,
    )
    verified = verify_execution_authorization(
        authorization,
        plan,
        trust_store=trust_store,
        engagement=engagement,
        worker_identity=WORKER,
        current_time_iso=NOW,
    )
    store = ApprovalStore(tmp_path / "private" / "approvals.sqlite3")
    store.store_authorization(authorization)
    return store, verified, plan, signer, trust_store, engagement


def persisted_status(store, authorization_id):
    with sqlite3.connect(store.db_path) as connection:
        return connection.execute(
            "SELECT status FROM approvals WHERE authorization_id = ?", (authorization_id,)
        ).fetchone()[0]


def test_same_id_different_verified_receipt_cannot_claim_approval(approval_context):
    store, expected, plan, signer, trust_store, engagement = approval_context
    replacement = create_execution_authorization(
        plan,
        signer=signer,
        engagement=engagement,
        worker_identity="worker-02",
        authorization_id=expected.authorization_id,
        issued_at=ISSUED_AT,
        authorized_until_utc=EXPIRES_AT,
    )
    replacement = verify_execution_authorization(
        replacement,
        plan,
        trust_store=trust_store,
        engagement=engagement,
        worker_identity="worker-02",
        current_time_iso=NOW,
    )
    with pytest.raises(ApprovalStoreConflictError, match="differs from the verified receipt"):
        store.atomically_consume(
            expected.authorization_id,
            expected_authorization=replacement,
            worker_identity="worker-02",
            current_time_iso=NOW,
        )
    assert persisted_status(store, expected.authorization_id) == "approved"

    consumed = store.atomically_consume(
        expected.authorization_id,
        expected_authorization=expected,
        worker_identity=WORKER,
        current_time_iso=NOW,
    )
    assert consumed.status == "consumed"
    assert consumed.consumed_by_worker == WORKER
    assert consumed.signature_digest == expected.signature_digest


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("operator", "different-operator"),
        ("signing_key_id", "different-key"),
        ("signature_digest", "a" * 64),
        ("plan_digest", "b" * 64),
        ("engagement_id", "eng-different"),
        ("approval_mode", "batch_confirmation"),
        ("authorized_until_utc", "2026-10-02T15:00:00Z"),
        ("bound_parameters_json", '{"worker_identity":"worker-02"}'),
    ],
)
def test_persisted_receipt_change_after_verification_cannot_be_consumed(
    approval_context, column, replacement
):
    store, expected, *_ = approval_context
    with sqlite3.connect(store.db_path) as connection:
        connection.execute(
            f"UPDATE approvals SET {column} = ? WHERE authorization_id = ?",
            (replacement, expected.authorization_id),
        )
    with pytest.raises(ApprovalStoreConflictError, match="differs from the verified receipt"):
        store.atomically_consume(
            expected.authorization_id,
            expected_authorization=expected,
            worker_identity=WORKER,
            current_time_iso=NOW,
        )
    assert persisted_status(store, expected.authorization_id) == "approved"


@pytest.mark.parametrize(
    ("worker", "now", "message", "status"),
    [
        ("worker-02", NOW, "bound to a different worker", "approved"),
        (WORKER, "2026-10-02T09:59:59Z", "not yet valid", "approved"),
        (WORKER, EXPIRES_AT, "expired", "expired"),
    ],
)
def test_atomic_claim_rechecks_worker_and_time_window(
    approval_context, worker, now, message, status
):
    store, expected, *_ = approval_context
    with pytest.raises(ApprovalStoreConflictError, match=message):
        store.atomically_consume(
            expected.authorization_id,
            expected_authorization=expected,
            worker_identity=worker,
            current_time_iso=now,
        )
    assert persisted_status(store, expected.authorization_id) == status
