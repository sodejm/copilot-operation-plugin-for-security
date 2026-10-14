# Engagement, Action, Result, and Finding Contracts Specification

## Purpose

Define versioned, tamper-evident schema contracts and lifecycle state machines for COPS operational and offensive security workflows. These contracts ensure that:
1. Engagements, Scenarios, ActionPlans, RunResults, and Findings have stable identifiers and immutable representations.
2. Operator authorization, action parameters, and targets are bound cryptographically via canonical digest calculation.
3. Execution outcomes preserve truthfulness: non-success states (`partial`, `cancelled`, `failed`, `uncertain`, `not_assessed`) are never silently converted into false success claims.
4. Findings claiming `verified` status are strictly bound to `cops.evidence/v1` evidence envelopes.

---

## Contract Schemas

### 1. Engagement Contract (`cops.engagement/v1`)
Represents an authorized cybersecurity engagement defining the target boundaries, rules of engagement, and authorized time window.
- **Identifier:** `eng-[a-z0-9_-]{4,64}`
- **Lifecycle States:** `planned`, `active`, `completed`, `cancelled`, `aborted`
- **Transitions:**
  - `planned` -> `active`, `cancelled`
  - `active` -> `completed`, `cancelled`, `aborted`
  - Terminal states: `completed`, `cancelled`, `aborted`

### 2. Scenario Contract (`cops.scenario/v1`)
Represents a structured attack scenario or assessment technique mapped to MITRE ATT&CK tactics/techniques, environment requirements, and safety profiles.
- **Identifier:** `scen-[a-z0-9_-]{4,64}` or `COPS-[A-Z0-9_.-]+`
- **Family Identifier:** `COPS-[A-Z0-9_.-]+` (e.g. `COPS-E01.03`)

### 3. ActionPlan Contract (`cops.action-plan/v1`)
Represents an immutable, planned sequence of operations bound to a scenario and engagement.
- **Identifier:** `plan-[a-z0-9_-]{4,64}`
- **Lifecycle States:** `draft`, `pending_approval`, `approved`, `executing`, `fulfilled`, `rejected`, `cancelled`
- **Transitions:**
  - `draft` -> `pending_approval`, `cancelled`
  - `pending_approval` -> `approved`, `rejected`, `cancelled`
  - `approved` -> `executing`, `cancelled`
  - `executing` -> `fulfilled`, `cancelled`
- **Security Invariants:**
  - Cannot transition directly from `draft` to `executing` (requires approval).
  - Cannot transition from `rejected` to `executing`.
  - Each operation records the exact version of its scenario-selected tool from a caller-supplied, independently measured `tool_versions` mapping. Planning does not discover executable versions; a missing or blank selected version is rejected, and the CLI rejects malformed or conflicting repeated `TOOL=VERSION` inputs.
  - `plan_digest` must match the SHA-256 canonical digest of the complete immutable approved snapshot: schema version, plan and engagement identifiers, scenario, target, specialist, operations and exact tool versions, limits, credential references, creation time, platform prerequisites, and batch semantics. Mutable lifecycle state is excluded from the digest.
  - `credential_references` must never contain raw tokens, keys, or passwords.

#### Plain-language goal selection

`cops engagement goal` validates one ordinary-language assessment request against
a versioned Engagement. This initial interface resolves a target only; it does not
create an ActionPlan or claim execution readiness.

- The request must begin with a supported, positive assessment instruction.
  Direct polite questions such as `Can you assess the selected endpoint?` are
  accepted. Informational questions, negation, and statements that merely
  mention a target do not select one. Details outside the supported grammar
  are rejected instead of ignored.
- The target must be an exact, explicitly named member of
  `scope.included_targets`, or the exact target recorded in the
  `metadata.goal_selection.target` field. A unique included target is not an
  implicit selection. Engagement metadata is not independently signed.
- Target text inside quotation marks or after an illustrative marker such as
  `for example`, `e.g.`, or `such as` is non-authoritative. Conflicting,
  excluded, illustrative, quoted, and multiple target references are rejected.
- A selected IP range that overlaps any excluded address or range is rejected;
  selecting a broad range must never imply authority over its exclusions.
- One result selects at most one target. The `needs_execution_path` response
  records the target and its source, unbound requested intent, a canonical
  engagement digest with unverified review status, `not_assessed` coverage, unavailable
  execution readiness, and the next action to bind a verified scenario and worker
  operation. It contains no ActionPlan, authorization, or run result.
- Goal selection does not contact targets, dispatch a worker, request approval,
  or assess a system. Host adapters must preserve the same boundary until a
  separately verified execution path exists.
- Terminal engagements and expired windows are rejected. Upcoming windows may
  select a target but do not confer execution readiness. Requests longer than
  4,096 characters, more than 1,024 combined scope targets, or more than 1 MiB
  of Engagement JSON are rejected; duplicate JSON keys are rejected. The scope
  count is checked before potentially expensive intake validation. Duplicate
  representations of one included target count as one target mention, without
  changing the original Engagement or its digest.

### 4. RunResult Contract (`cops.run-result/v1`)
Represents the execution outcome of an action plan.
- **Identifier:** `res-[a-z0-9_-]{4,64}`
- **Statuses:** `success`, `partial`, `cancelled`, `failed`, `uncertain`, `not_assessed`
- **Truthfulness Invariant:**
  - `is_successful()` returns `True` strictly when `status == "success"`.
  - Any non-success status requires an explicit, non-empty `status_details.reason`.

### 5. Finding Contract (`cops.finding/v1`)
Represents a normalized security finding derived from RunResult evidence.
- **Identifier:** `find-[a-z0-9_-]{4,64}`
- **Verification Levels:** `verified`, `partially-verified`, `unverified`, `contradicted`
- **Evidence Invariant:**
  - A finding with `verification == "verified"` must reference at least one `cops.evidence/v1` record ID.

The [engagement findings and reporting specification](engagement-findings-and-reporting.spec.md)
defines the separate offline assessment join and its evidence and coverage labels.
