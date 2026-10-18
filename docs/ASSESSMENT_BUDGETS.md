# Aggregate assessment budgets

`cops.assessment_budget` supplies an opt-in local ledger and synthetic dispatcher
for an operator-controlled assessment engagement. The opt-in #150 gateway emulator
uses the same ledger for provider-shaped dispatches. This is local admission
evidence, not production provider or billing evidence. The existing engagement
action limits are separate.

## Configure the engagement

Create one immutable `BudgetPolicy` and one private SQLite path per engagement.
The policy fixes attempt count, estimated tokens and cost, elapsed time,
concurrency, retained output, recursion depth, and children per parent. Cost uses
integer micro-units in a named currency. The operator must pin a price source,
version, and effective date. If a price or pre-dispatch estimate is unavailable,
refuse the call. Estimates admit calls; they are not a billing ceiling.

The controller, rather than agent or provider content, chooses the policy, path,
request estimates, and narrower child limits. The ledger creates its parent
directory with mode `0700` and file with mode `0600`, and rejects paths with
different permissions or ownership. Keep that directory outside shared or
backed-up evidence exports. The ledger holds attempt IDs, budgets, outcomes, and
usage, but no prompts or provider responses. Use the
[versioned schema](../catalog/schemas/assessment-budget.schema.json) for policy,
request, receipt, and cancellation report fields, and the [specification](../specs/aggregate-assessment-budgets.spec.md)
for their transition rules.

```python
from pathlib import Path

from cops.assessment_budget import (
    AssessmentBudgetLedger, AttemptRequest, BudgetLimits, BudgetPolicy,
    Receipt, dispatch_fixture,
)

policy = BudgetPolicy(
    engagement_id="example-engagement",
    limits=BudgetLimits(
        max_attempts=3, max_estimated_tokens=3000,
        max_estimated_cost_microunits=500000, max_elapsed_ms=60000,
        max_concurrency=1, max_retained_output_bytes=4096,
        max_depth=1, max_children_per_parent=2,
    ),
    currency="USD", price_source="operator-price-sheet",
    price_version="example-v1", price_effective_date="2026-10-01",
)
ledger = AssessmentBudgetLedger(Path("private-assessment-state/budget.sqlite3"), policy)
request = AttemptRequest("fixture-1", None, 100, 10000, 100)

def fake_provider(attempt: AttemptRequest, cancellation) -> Receipt:
    if cancellation.requested():
        return Receipt("receipt-1", attempt.attempt_id, "runner_stopped", 0, 0, 0)
    return Receipt("receipt-1", attempt.attempt_id, "completed", 80, 8000, 40)

result = dispatch_fixture(ledger, request, fake_provider)
assert result.state == "settled"
```

`dispatch_fixture` records a reservation and durable dispatch intent before
calling the supplied synthetic callback. The callback receives a durable
cancellation signal and must return a receipt for the same attempt. A repeated
attempt ID cannot call it twice. Children use a
previously admitted parent ID, share the engagement ledger, and may supply only
narrower `child_limits` to `reserve`. Every retry needs a fresh attempt ID and is
charged against the same aggregate budget.

For opt-in provider emulation, the trusted controller passes the same ledger to
`execute_live_case` and supplies `parent_attempt_id` when the provider call belongs
to an agent attempt. It may supply narrower `child_limits` for that call. Both
values come from controller state, never from a plan, agent message, tool output,
or provider response. Local tool attempts and provider attempts under that parent
then consume the same aggregate and subtree allowances. A missing parent, a
released parent, widened limits, exhausted allowance, or unavailable ledger denies
the provider dispatch before the gateway is called. The signed one-use gateway
grant remains a separate requirement. See [provider gateway operations](PROVIDER_GATEWAY.md).

## Recover and reconcile

`reserved` means no dispatch intent was recorded and may be released with
`release_undispatched`. `dispatched` and `uncertain` may have reached the callback:
do not release them on timeout, restart, or cancellation. Reopening the ledger
marks unresolved dispatches `uncertain`; cancellation stops new admission, sets
the signal for every active attempt in the engagement, and releases only
undispatched reservations. A running fixture callback can poll
`cancellation.requested()` and return a `runner_stopped` receipt. The ledger
cannot force a callback to stop: a callback that finishes after cancellation
can still report `completed`. `cancellation_report(attempt_id)` separates
`requested`, `stop_confirmed`, `pending`, `final_consumption_known`, and the
observed `outcome`. A request alone never confirms a stop; unknown usage remains
pending until a complete receipt arrives. Reconcile an in-flight attempt only
with a trustworthy receipt. The fixture API has no release operation for an
attempt with dispatch intent, even if separate evidence establishes that a
remote call never began.

Receipt outcomes distinguish `target_denied` from `runner_stopped`, as well as
`completed`, `failed`, and `cancelled`. An outcome is an observation, not proof
that a remote provider stopped billing. A receipt may leave token, cost, or output
usage unknown (`None`); the attempt then enters `usage_unknown` and retains its
reserved charge. A later receipt may fill missing fields without changing the
outcome or known values. Exact duplicate receipt IDs are idempotent; conflicting
IDs and revisions fail. Actual usage above the estimate records an overage and
blocks new admission. Retained output above its reserved byte allowance is
rejected. Inspect `snapshot()` for charged totals and overage state.

If storage fails, its permissions change, policy binding differs, or the clock
moves backward, admission fails closed. A denied admission still advances the
durable clock checkpoint, so setting the clock back after expiry cannot regain
allowance. Restore the original ledger and policy
before recovery; do not substitute a fresh empty file for an engagement with
possibly in-flight calls. The fixture and gateway emulator tests cover these local
transitions, including concurrent provider admission and parent budget accounting.
They do not establish provider billing, authenticated provider receipts, remote
cancellation, or coverage of callers that bypass the wrapper. Retain the private
ledger until independent reconciliation and the engagement retention policy permit
deletion; restore the original ledger and pinned policy after restart or migration.
