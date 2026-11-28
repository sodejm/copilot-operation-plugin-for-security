"""Synthetic assessment budget admission and recovery checks."""

from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path

import jsonschema
import pytest

from cops.assessment_budget import (
    AssessmentBudgetLedger,
    AttemptRequest,
    BudgetDenied,
    BudgetLimits,
    BudgetPolicy,
    BudgetStoreError,
    Receipt,
    dispatch_fixture,
)


class Clock:
    def __init__(self, now: int = 1_800_000_000_000) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def policy(**limits: int) -> BudgetPolicy:
    values = dict(
        max_attempts=5,
        max_estimated_tokens=100,
        max_estimated_cost_microunits=1000,
        max_elapsed_ms=10_000,
        max_concurrency=2,
        max_retained_output_bytes=100,
        max_depth=2,
        max_children_per_parent=2,
    )
    values.update(limits)
    return BudgetPolicy(
        engagement_id="eng-fixture-240",
        limits=BudgetLimits(**values),
        currency="USD",
        price_source="fixture-price-list",
        price_version="2026-10-test",
        price_effective_date="2026-10-01",
    )


def request(attempt_id: str, parent_id: str | None = None, **amounts: int) -> AttemptRequest:
    values = dict(estimated_tokens=10, estimated_cost_microunits=100, reserved_output_bytes=10)
    values.update(amounts)
    return AttemptRequest(attempt_id, parent_id, **values)


def ledger(tmp_path, clock: Clock, budget: BudgetPolicy | None = None) -> AssessmentBudgetLedger:
    return AssessmentBudgetLedger(tmp_path / "private" / "budget.sqlite3", budget or policy(), clock=clock)


def test_concurrent_admission_is_atomic(tmp_path):
    clock = Clock()
    store = ledger(tmp_path, clock)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda i: _attempt_reserve(store, request(f"attempt-{i}")), range(5)))
    assert results.count("admitted") == 2
    assert results.count("denied") == 3
    assert store.snapshot().active_concurrency == 2
    assert store.snapshot().charged_attempts == 2


def _attempt_reserve(store: AssessmentBudgetLedger, attempt: AttemptRequest) -> str:
    try:
        store.reserve(attempt)
    except BudgetDenied:
        return "denied"
    return "admitted"


def test_idempotent_reservation_and_conflicting_reuse(tmp_path):
    store = ledger(tmp_path, Clock())
    first = request("attempt-a")
    assert store.reserve(first).attempt_id == "attempt-a"
    assert store.reserve(first).attempt_id == "attempt-a"
    assert store.snapshot().charged_attempts == 1
    with pytest.raises(BudgetDenied, match="conflict"):
        store.reserve(request("attempt-a", estimated_tokens=11))
    narrowed = replace(policy().limits, max_attempts=1)
    store.reserve(request("narrowed"), child_limits=narrowed)
    assert store.reserve(request("narrowed"), child_limits=narrowed).attempt_id == "narrowed"
    with pytest.raises(BudgetDenied, match="conflict"):
        store.reserve(request("narrowed"))


def test_fixture_replay_never_invokes_callback_twice(tmp_path):
    store = ledger(tmp_path, Clock())
    called = []

    def callback(attempt, _cancellation):
        called.append(attempt.attempt_id)
        return Receipt("receipt-once", attempt.attempt_id, "completed", 2, 20, 1)

    assert dispatch_fixture(store, request("attempt-a"), callback).state == "settled"
    with pytest.raises(BudgetDenied):
        dispatch_fixture(store, request("attempt-a"), callback)
    assert called == ["attempt-a"]


def test_inflight_replay_and_cross_attempt_receipt_do_not_dispatch_or_settle_wrong_attempt(tmp_path):
    store = ledger(tmp_path, Clock())
    store.reserve(request("attempt-a"))
    store.mark_dispatched("attempt-a")
    called = []
    with pytest.raises(BudgetDenied):
        dispatch_fixture(store, request("attempt-a"), lambda _attempt, _signal: called.append(True))
    assert called == []

    store.reserve(request("attempt-b"))
    with pytest.raises(BudgetDenied, match="attempt"):
        dispatch_fixture(
            store,
            request("attempt-b"),
            lambda _attempt, _signal: Receipt("cross", "attempt-a", "completed", 1, 10, 1),
        )
    assert store.get_attempt("attempt-a").state == "dispatched"
    assert store.get_attempt("attempt-b").state == "uncertain"


def test_retry_depth_fanout_and_narrow_inheritance(tmp_path):
    store = ledger(tmp_path, Clock(), policy(max_concurrency=5))
    narrow = BudgetLimits(
        max_attempts=3,
        max_estimated_tokens=30,
        max_estimated_cost_microunits=300,
        max_elapsed_ms=10_000,
        max_concurrency=3,
        max_retained_output_bytes=30,
        max_depth=1,
        max_children_per_parent=2,
    )
    store.reserve(request("root"), child_limits=narrow)
    store.reserve(request("retry-1", "root"))
    store.reserve(request("retry-2", "root"))
    with pytest.raises(BudgetDenied, match="fanout"):
        store.reserve(request("retry-3", "root"))
    with pytest.raises(BudgetDenied, match="depth"):
        store.reserve(request("grandchild", "retry-1"))
    with pytest.raises(BudgetDenied, match="widen"):
        store.reserve(request("bad-child", "root"), child_limits=policy().limits)
    assert store.snapshot().charged_attempts == 3


def test_subtree_limit_is_aggregate(tmp_path):
    store = ledger(tmp_path, Clock(), policy(max_concurrency=5))
    narrow = BudgetLimits(
        max_attempts=2,
        max_estimated_tokens=20,
        max_estimated_cost_microunits=200,
        max_elapsed_ms=10_000,
        max_concurrency=2,
        max_retained_output_bytes=20,
        max_depth=2,
        max_children_per_parent=2,
    )
    store.reserve(request("root"), child_limits=narrow)
    store.reserve(request("child-1", "root"))
    with pytest.raises(BudgetDenied, match="subtree"):
        store.reserve(request("child-2", "root"))


def test_unknown_then_late_known_receipt_and_duplicate(tmp_path):
    store = ledger(tmp_path, Clock())
    store.reserve(request("attempt-a"))
    store.mark_dispatched("attempt-a")
    unknown = Receipt("receipt-unknown", "attempt-a", "target_denied", None, None, None)
    assert store.reconcile(unknown).state == "usage_unknown"
    assert store.reconcile(unknown).state == "usage_unknown"
    assert store.snapshot().charged_tokens == 10
    known = Receipt("receipt-known", "attempt-a", "target_denied", 3, 30, 2)
    assert store.reconcile(known).state == "settled"
    assert store.reconcile(known).state == "settled"
    assert store.snapshot().charged_tokens == 3
    assert store.snapshot().active_concurrency == 0
    with pytest.raises(BudgetDenied, match="conflict"):
        store.reconcile(Receipt("receipt-known", "attempt-a", "runner_stopped", 3, 30, 2))


def test_partial_receipt_keeps_full_reservation_until_complete(tmp_path):
    store = ledger(tmp_path, Clock())
    store.reserve(request("attempt-a"))
    store.mark_dispatched("attempt-a")
    partial = Receipt("partial", "attempt-a", "target_denied", 2, None, 1)
    assert store.reconcile(partial).state == "usage_unknown"
    snapshot = store.snapshot()
    assert (snapshot.charged_tokens, snapshot.charged_cost_microunits, snapshot.charged_output_bytes) == (10, 100, 10)
    with pytest.raises(BudgetDenied, match="conflict"):
        store.reconcile(Receipt("changed", "attempt-a", "runner_stopped", 2, 20, 1))
    with pytest.raises(BudgetDenied, match="conflict"):
        store.reconcile(Receipt("revised", "attempt-a", "target_denied", 3, 20, 1))
    assert store.reconcile(Receipt("complete", "attempt-a", "target_denied", 2, 20, 1)).state == "settled"


def test_subtree_deadline_checked_at_dispatch(tmp_path):
    clock = Clock()
    store = ledger(tmp_path, clock)
    store.reserve(request("attempt-a"), child_limits=replace(policy().limits, max_elapsed_ms=100))
    clock.now += 101
    with pytest.raises(BudgetDenied, match="deadline"):
        store.mark_dispatched("attempt-a")
    assert store.get_attempt("attempt-a").state == "reserved"


def test_inherited_deadline_bounds_remaining_dispatch_time(tmp_path):
    clock = Clock()
    store = ledger(tmp_path, clock)
    parent_limits = replace(policy().limits, max_elapsed_ms=2500)
    child_limits = replace(parent_limits, max_elapsed_ms=1000)
    store.reserve(request("root"), child_limits=parent_limits)
    store.reserve(request("child", "root"), child_limits=child_limits)
    clock.now += 100
    assert store.remaining_elapsed_ms() == 9900
    assert store.remaining_elapsed_ms("root") == 2400
    assert store.remaining_elapsed_ms("child") == 900
    clock.now += 901
    assert store.remaining_elapsed_ms("child") == 0
    with pytest.raises(BudgetDenied, match="deadline"):
        store.mark_dispatched("child")


def test_parent_release_requires_released_descendants(tmp_path):
    store = ledger(tmp_path, Clock())
    store.reserve(request("root"))
    store.reserve(request("child", "root"))
    with pytest.raises(BudgetDenied, match="live descendants"):
        store.release_undispatched("root")
    assert store.get_attempt("root").state == "reserved"
    store.release_undispatched("child")
    assert store.release_undispatched("root").state == "released"
    with pytest.raises(BudgetDenied, match="parent attempt unavailable"):
        store.reserve(request("later", "root"))


def test_dispatch_rejects_historically_released_ancestor(tmp_path):
    store = ledger(tmp_path, Clock())
    store.reserve(request("root"))
    store.reserve(request("child", "root"))
    # Simulate a ledger created before the parent-release invariant was enforced.
    with sqlite3.connect(store.db_path) as db:
        db.execute("UPDATE attempts SET state = 'released' WHERE attempt_id = 'root'")
    with pytest.raises(BudgetDenied, match="ancestor attempt unavailable"):
        store.mark_dispatched("child")
    with pytest.raises(BudgetDenied, match="parent attempt unavailable"):
        store.reserve(request("grandchild", "child"))


def test_oversized_dispatch_intent_rejected_before_persisting(tmp_path):
    store = ledger(tmp_path, Clock())
    store.reserve(request("attempt-a"))
    with pytest.raises(ValueError, match="size limit"):
        store.mark_dispatched(
            "attempt-a",
            approval_receipt_id="approval-a",
            dispatch_intent={
                "approval_issued_at": "2026-10-16T12:00:00+00:00",
                "approval_expires_at": "2026-10-16T12:05:00+00:00",
                "authority_id": "x" * 65_536,
            },
        )
    assert store.get_attempt("attempt-a").state == "reserved"
    with pytest.raises(BudgetDenied, match="dispatch intent not found"):
        store.get_dispatch_intent("attempt-a")


def test_overage_blocks_admission_and_retained_output_cannot_exceed_reservation(tmp_path):
    store = ledger(tmp_path, Clock(), policy(max_concurrency=3))
    store.reserve(request("attempt-a"))
    store.mark_dispatched("attempt-a")
    with pytest.raises(BudgetDenied, match="output"):
        store.reconcile(Receipt("too-much-output", "attempt-a", "completed", 4, 40, 11))
    store.reconcile(Receipt("overage", "attempt-a", "completed", 101, 1100, 10))
    assert store.snapshot().over_budget
    with pytest.raises(BudgetDenied, match="budget"):
        store.reserve(request("attempt-b"))


def test_cancel_and_restart_keep_inflight_reserved(tmp_path):
    clock = Clock()
    store = ledger(tmp_path, clock)
    store.reserve(request("undispatched"))
    store.reserve(request("inflight"))
    store.mark_dispatched("inflight")
    store.cancel()
    reopened = ledger(tmp_path, clock)
    assert reopened.get_attempt("undispatched").state == "released"
    assert reopened.get_attempt("inflight").state == "uncertain"
    assert reopened.cancellation_report("undispatched").stop_confirmed
    assert reopened.cancellation_report("undispatched").final_consumption_known
    assert reopened.cancellation_report("inflight").requested
    assert reopened.cancellation_report("inflight").pending
    assert not reopened.cancellation_report("inflight").stop_confirmed
    assert reopened.snapshot().active_concurrency == 1
    with pytest.raises(BudgetDenied, match="cancelled"):
        reopened.reserve(request("new"))
    reopened.reconcile(Receipt("late", "inflight", "runner_stopped", 5, 50, 0))
    assert reopened.snapshot().active_concurrency == 0
    assert reopened.cancellation_report("inflight").stop_confirmed
    assert reopened.cancellation_report("inflight").final_consumption_known


def test_cancel_signals_active_children_without_claiming_an_uncooperative_stop(tmp_path):
    store = ledger(tmp_path, Clock(), policy(max_attempts=4, max_children_per_parent=3))
    store.reserve(request("root"))
    store.mark_dispatched("root")
    store.reconcile(Receipt("root-receipt", "root", "completed", 1, 10, 1))
    entered = {name: threading.Event() for name in ("child-1", "child-2")}
    release = threading.Event()
    dispatched = []
    lock = threading.Lock()

    def cooperative(attempt, cancellation):
        with lock:
            dispatched.append(attempt.attempt_id)
        entered[attempt.attempt_id].set()
        assert release.wait(timeout=5)
        assert cancellation.requested()
        return Receipt(f"receipt-{attempt.attempt_id}", attempt.attempt_id, "runner_stopped", 2, 20, 1)

    def uncooperative(attempt, cancellation):
        with lock:
            dispatched.append(attempt.attempt_id)
        entered[attempt.attempt_id].set()
        assert release.wait(timeout=5)
        assert cancellation.requested()
        return Receipt(f"receipt-{attempt.attempt_id}", attempt.attempt_id, "completed", 2, 20, 1)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(dispatch_fixture, store, request("child-1", "root"), cooperative)
        second = pool.submit(dispatch_fixture, store, request("child-2", "root"), uncooperative)
        try:
            assert all(event.wait(timeout=5) for event in entered.values())
            assert store.snapshot().active_concurrency == 2
            with pytest.raises(BudgetDenied, match="budget"):
                dispatch_fixture(store, request("child-3", "root"), cooperative)
            assert sorted(dispatched) == ["child-1", "child-2"]
            store.cancel()
            for name in entered:
                report = store.cancellation_report(name)
                assert report.requested and report.pending
                assert not report.stop_confirmed
                assert not report.final_consumption_known
        finally:
            release.set()
        assert first.result(timeout=5).state == "settled"
        assert second.result(timeout=5).state == "settled"

    assert store.cancellation_report("child-1").stop_confirmed
    assert not store.cancellation_report("child-1").pending
    assert store.cancellation_report("child-1").final_consumption_known
    assert not store.cancellation_report("child-2").stop_confirmed
    assert not store.cancellation_report("child-2").pending
    assert store.cancellation_report("child-2").final_consumption_known
    assert store.snapshot().active_concurrency == 0


def test_cancelled_attempt_with_unknown_usage_remains_pending(tmp_path):
    store = ledger(tmp_path, Clock())
    store.reserve(request("attempt-a"))
    store.mark_dispatched("attempt-a")
    store.cancel()
    store.reconcile(Receipt("unknown", "attempt-a", "runner_stopped", None, None, None))
    report = store.cancellation_report("attempt-a")
    assert report.stop_confirmed and report.pending
    assert not report.final_consumption_known
    store.reconcile(Receipt("known", "attempt-a", "runner_stopped", 3, 30, 1))
    assert store.cancellation_report("attempt-a").final_consumption_known
    assert not store.cancellation_report("attempt-a").pending


def test_deadline_clock_rollback_and_missing_database_fail_closed(tmp_path):
    clock = Clock()
    store = ledger(tmp_path, clock, policy(max_elapsed_ms=100))
    clock.now += 101
    with pytest.raises(BudgetDenied, match="deadline"):
        store.reserve(request("late"))
    # The denied request must still advance the durable clock checkpoint.
    clock.now -= 2
    with pytest.raises(BudgetStoreError, match="clock"):
        store.reserve(request("rollback"))
    store.db_path.unlink()
    called = []
    with pytest.raises(BudgetStoreError):
        dispatch_fixture(store, request("missing"), lambda _attempt, _signal: called.append(True))
    assert called == []


def test_fixture_exception_preserves_uncertain_intent(tmp_path):
    store = ledger(tmp_path, Clock())
    with pytest.raises(RuntimeError, match="provider fault"):
        dispatch_fixture(
            store, request("attempt-a"), lambda _attempt, _signal: (_ for _ in ()).throw(RuntimeError("provider fault"))
        )
    assert store.get_attempt("attempt-a").state == "uncertain"
    assert store.snapshot().active_concurrency == 1


def test_policy_validation_and_reopen_binding(tmp_path):
    clock = Clock()
    store = ledger(tmp_path, clock)
    with pytest.raises(BudgetStoreError, match="policy"):
        ledger(tmp_path, clock, policy(max_attempts=6))
    with pytest.raises(ValueError):
        policy(max_attempts=True)
    with pytest.raises(ValueError, match="price_effective_date"):
        replace(policy(), price_effective_date="2026-02-30")
    assert store.snapshot().charged_attempts == 0


def test_storage_failure_does_not_invoke_fixture(tmp_path, monkeypatch):
    store = ledger(tmp_path, Clock())
    called = []

    def broken_connect(*_args, **_kwargs):
        raise sqlite3.OperationalError("storage unavailable")

    monkeypatch.setattr("cops.assessment_budget.sqlite3.connect", broken_connect)
    with pytest.raises(BudgetStoreError):
        dispatch_fixture(store, request("attempt-a"), lambda _attempt, _signal: called.append(True))
    assert called == []


def test_versioned_json_schema_matches_policy_request_and_receipt():
    schema_path = Path(__file__).resolve().parents[1] / "catalog/schemas/assessment-budget.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    policy_validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    policy_validator.validate(asdict(policy()))
    with pytest.raises(jsonschema.ValidationError):
        policy_validator.validate({**asdict(policy()), "price_effective_date": "2026-02-30"})
    with pytest.raises(jsonschema.ValidationError):
        policy_validator.validate({**asdict(policy()), "limits": {**asdict(policy().limits), "max_attempts": True}})

    def validator_for(definition: str) -> jsonschema.Draft202012Validator:
        return jsonschema.Draft202012Validator({"$defs": schema["$defs"], "$ref": f"#/$defs/{definition}"})

    request_validator = validator_for("attemptRequest")
    request_validator.validate({**asdict(request("attempt-a")), "child_limits": asdict(policy().limits)})
    with pytest.raises(jsonschema.ValidationError):
        request_validator.validate({**asdict(request("attempt-a")), "estimated_tokens": -1})
    receipt_validator = validator_for("receipt")
    receipt_validator.validate(asdict(Receipt("receipt-a", "attempt-a", "completed", None, 10, 0)))
    with pytest.raises(jsonschema.ValidationError):
        receipt_validator.validate(
            asdict(Receipt("receipt-a", "attempt-a", "completed", None, 10, 0)) | {"outcome": "denied"}
        )
    cancellation_validator = validator_for("cancellationReport")
    cancellation_validator.validate(
        {
            "attempt_id": "attempt-a",
            "requested": True,
            "stop_confirmed": False,
            "pending": True,
            "final_consumption_known": False,
            "outcome": None,
        }
    )
