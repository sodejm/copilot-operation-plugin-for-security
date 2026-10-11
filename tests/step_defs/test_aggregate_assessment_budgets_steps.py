"""Executable fixture scenarios for the engagement budget boundary."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from pytest_bdd import given, scenarios, then, when

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

scenarios("../../specs/features/aggregate_assessment_budgets.feature")


class Clock:
    def __init__(self):
        self.now = 1_800_000_000_000

    def __call__(self):
        return self.now


@pytest.fixture
def context(tmp_path):
    clock = Clock()
    return {"clock": clock, "path": tmp_path / "private" / "budget.sqlite3"}


def setup(context, **limit_overrides):
    limits = dict(
        max_attempts=5,
        max_estimated_tokens=100,
        max_estimated_cost_microunits=1000,
        max_elapsed_ms=10_000,
        max_concurrency=2,
        max_retained_output_bytes=100,
        max_depth=2,
        max_children_per_parent=3,
    )
    limits.update(limit_overrides)
    context["policy"] = BudgetPolicy(
        "eng-bdd-240", BudgetLimits(**limits), "USD", "fixture", "v1", "2026-10-01"
    )
    context["store"] = AssessmentBudgetLedger(
        context["path"], context["policy"], clock=context["clock"]
    )


def request(attempt_id, parent_id=None):
    return AttemptRequest(attempt_id, parent_id, 10, 100, 10)


def settle(context, attempt_id):
    store = context["store"]
    store.mark_dispatched(attempt_id)
    store.reconcile(Receipt(f"receipt-{attempt_id}", attempt_id, "completed", 10, 100, 10))


@given("a fixture assessment budget with two permitted concurrent attempts")
def concurrent_budget(context):
    setup(context)
    context["store"].reserve(request("root"))
    settle(context, "root")


@when("three child attempts reserve concurrently")
def concurrent_children(context):
    def try_reserve(index):
        try:
            context["store"].reserve(request(f"child-{index}", "root"))
        except BudgetDenied:
            return False
        return True

    with ThreadPoolExecutor(max_workers=3) as pool:
        context["admitted"] = list(pool.map(try_reserve, range(3)))


@then("only two attempts are admitted")
def two_admitted(context):
    assert sum(context["admitted"]) == 2


@then("the shared ledger never exceeds its concurrency limit")
def bounded_concurrency(context):
    assert context["store"].snapshot().active_concurrency == 2


@given("a fixture assessment budget with bounded attempts and depth")
def bounded_budget(context):
    setup(context, max_attempts=3, max_depth=1, max_concurrency=3)
    context["store"].reserve(request("root"))
    settle(context, "root")


@when("a child retries and then requests a child beyond the permitted depth")
def retry_and_recurse(context):
    store = context["store"]
    store.reserve(request("first", "root"))
    store.reserve(request("retry", "root"))
    try:
        store.reserve(request("too-deep", "retry"))
    except BudgetDenied as exc:
        context["depth_denial"] = str(exc)


@then("the retry consumes a new attempt")
def retry_counts(context):
    assert context["store"].snapshot().charged_attempts == 3


@then("the excessive depth is denied before fixture dispatch")
def depth_denied(context):
    assert "depth" in context["depth_denial"]
    with pytest.raises(BudgetDenied):
        context["store"].get_attempt("too-deep")


@given("an admitted fixture attempt with dispatch intent")
def dispatched(context):
    setup(context)
    context["store"].reserve(request("attempt"))
    context["store"].mark_dispatched("attempt")


@when("an unknown usage receipt and its duplicate arrive")
def unknown_duplicate(context):
    receipt = Receipt("unknown", "attempt", "target_denied", None, None, None)
    assert context["store"].reconcile(receipt).state == "usage_unknown"
    assert context["store"].reconcile(receipt).state == "usage_unknown"


@then("the allowance remains conservatively charged")
def unknown_charged(context):
    assert context["store"].snapshot().charged_tokens == 10


@when("a later known usage receipt arrives")
def late_known(context):
    context["store"].reconcile(Receipt("known", "attempt", "target_denied", 3, 30, 2))


@then("the attempt settles once with its known usage")
def settled_once(context):
    assert context["store"].snapshot().charged_tokens == 3
    assert context["store"].get_attempt("attempt").state == "settled"


@when("the engagement is cancelled and the ledger is reopened")
def cancel_reopen(context):
    context["store"].cancel()
    context["store"] = AssessmentBudgetLedger(
        context["path"], context["policy"], clock=context["clock"]
    )


@then("new attempts are denied")
def denied_after_cancel(context):
    with pytest.raises(BudgetDenied, match="cancelled"):
        context["store"].reserve(request("new"))


@then("the in-flight attempt remains reserved as uncertain")
def uncertain_after_restart(context):
    assert context["store"].get_attempt("attempt").state == "uncertain"
    assert context["store"].snapshot().active_concurrency == 1


@given("a fixture assessment budget with a short deadline")
def short_deadline(context):
    setup(context, max_elapsed_ms=50)


@when("the deadline expires before a new reservation")
def expire(context):
    context["clock"].now += 51


@then("the reservation is denied")
def denied_after_deadline(context):
    with pytest.raises(BudgetDenied, match="deadline"):
        context["store"].reserve(request("late"))


@when("the ledger storage becomes unavailable")
def remove_storage(context):
    context["path"].unlink()


@then("the fixture callback is not dispatched")
def no_dispatch(context):
    called = []
    with pytest.raises(BudgetStoreError):
        dispatch_fixture(
            context["store"], request("missing"),
            lambda _attempt, _signal: called.append(True),
        )
    assert not called


@when("the clock moves behind the last denied reservation")
def rollback_after_denial(context):
    context["clock"].now -= 2


@then("the rolled-back clock is rejected")
def rollback_rejected(context):
    with pytest.raises(BudgetStoreError, match="clock"):
        context["store"].reserve(request("rollback"))
