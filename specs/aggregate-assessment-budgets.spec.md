# Aggregate Assessment Budget Specification

## Status and boundary

`cops.assessment-budget/v1` is an opt-in, engagement-scoped local admission
contract for assessment attempt dispatch. It does not alter the existing
`cops.engagement/v1` action limits. This revision has a synthetic fixture
dispatcher only. Provider assessment adapters depend on issue #150 and require
their own integration and exact-revision review before this contract can enforce
real provider calls. A caller that bypasses this dispatcher is outside coverage.

The operator supplies a trusted, immutable budget and price basis before an
engagement begins. All children, retries, and provider/tool attempts use one
ledger path and engagement identifier. A child may impose narrower limits but
cannot widen any parent limit. The trusted controller owns the ledger file;
untrusted agent output, tool output, and provider receipts never choose a budget,
engagement, price basis, or ledger path.
The policy, request, receipt, and cancellation report JSON shapes are versioned in
[`catalog/schemas/assessment-budget.schema.json`](../catalog/schemas/assessment-budget.schema.json).

## Versioned policy

The policy records `engagement_id`, `max_attempts`, `max_estimated_tokens`,
`max_estimated_cost_microunits`, `max_elapsed_ms`, `max_concurrency`,
`max_retained_output_bytes`, `max_depth`, and `max_children_per_parent` as
nonnegative bounded integers (positive where zero would make the contract
unusable). Cost is an estimate, in the named `currency` and integer micro-units.
`price_source`, `price_version`, and `price_effective_date` identify the
operator-pinned assumption. The error policy is `deny`: unknown price or missing
pre-dispatch token/cost estimate refuses admission. Neither token nor cost
estimates are a guaranteed provider billing ceiling.

## Ledger transitions

The local SQLite ledger durably binds one policy and deadline to its engagement.
`reserve` atomically checks all active and committed usage, deadline,
concurrency, depth, fanout, and parent identity before creating an attempt.
An attempt ID is its idempotency key: replay with identical request parameters
and effective child limits returns the existing state; conflicting reuse fails.
Replay never invokes a dispatched attempt again. Retries must use new
attempt IDs. A child must reference an already admitted parent. Reservation
does not by itself call a provider.

The controller durably records `dispatched` before invoking its fixture callback.
A callback failure or crash after this intent produces an `uncertain` outcome;
its allowance remains reserved until a trustworthy terminal receipt. The fixture
API has no operation to turn external no-dispatch evidence into a release. A time
or lease expiry never releases possibly in-flight allowance. An undispatched
reservation may be released idempotently. A terminal receipt has its own ID
and bound attempt ID. Duplicate identical receipts are
idempotent; conflicts and duplicate IDs across attempts fail. A partial receipt
can be completed only with the same outcome and previously known values. Actual usage
replaces reserved usage only when the receipt has known, bounded token, cost,
and retained-output values. Unknown usage is recorded as `usage_unknown` and
conservatively retains its estimate. A later known receipt may reconcile it.
Reported usage above estimate is recorded as an overage and blocks new admission;
it cannot retroactively cap a provider charge.

Cancellation durably stops new admission, marks every active attempt as requested,
and releases only attempts that have not reached dispatch intent. An active
fixture callback receives a durable signal and may cooperatively return a
`runner_stopped` receipt. The callback can also complete after a cancellation
request. `cancellation_report` distinguishes the request, a confirmed fixture
stop, pending consumption, known final consumption, and the observed outcome.
In-flight attempts stay pending until a complete receipt; a partial receipt
retains the reserved charge. A cancellation request or fixture stop is not proof
of remote cancellation. The ledger is fail closed on unavailable/corrupt storage or
a clock rollback. A rejected action preserves the latest observed clock checkpoint.
It does not persist prompts, responses, or raw provider data.

## Acceptance scenarios

The executable scenarios in `features/aggregate_assessment_budgets.feature`
cover aggregate concurrent admission, child fanout and depth, retry accounting,
idempotency, late and unknown receipts, cancellation, restart uncertainty,
deadline, denied-action clock rollback, and unavailable storage. Synthetic
concurrency tests exercise the SQLite transaction boundary, bounded callback
dispatch, and cooperative versus uncooperative cancellation. Cost and token checks prove local estimate-based
admission, not live billing control.
