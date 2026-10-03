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
  - `plan_digest` must match SHA-256 canonical digest of `{"target", "specialist_id", "operations", "limits"}`.
  - `credential_references` must never contain raw tokens, keys, or passwords.

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
