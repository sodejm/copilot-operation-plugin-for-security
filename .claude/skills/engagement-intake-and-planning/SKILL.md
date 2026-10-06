---
name: engagement-intake-and-planning
description: Ingest authorized engagement scope, validate targets and windows, enforce boundaries, and compile reviewable immutable action plans.
---

# Engagement intake and planning

Guide the intake, scope validation, execution mode classification, and action plan compilation for cybersecurity engagements:

- **Engagement Intake**: Enforces explicit operator ownership, unambiguous targets, non-colliding exclusions, authorized assessment windows, allowed effects, execution budgets, and credential references.
- **Execution Mode Distinction**: Strictly separates `planning` (offline modeling), `import` (static log/artifact parsing), `laboratory` (isolated simulation), and `live` (active execution).
- **Live Safety Gate**: Refuses incomplete live requests when budget, emergency contact, active window, or narrow subnet boundaries are absent.
- **Immutable Action Planning**: Produces cryptographically bound `ActionPlan` (`cops.action-plan/v1`) contracts detailing platform prerequisites, expected evidence, side effects, and cleanup obligations.

## CLI Usage

### 1. Create and Validate an Engagement Intake

```bash
python3 -m cops engagement create \
  --name "Internal Network Review" \
  --owner "secops-lead" \
  --targets "10.0.0.10,app.internal" \
  --exclusions "10.0.0.1,prod-db.internal" \
  --start "2026-10-05T00:00:00Z" \
  --until "2026-10-05T23:59:59Z" \
  --allowed-effects "read_only_discovery,banner_grab" \
  --budget-duration 1800 \
  --budget-output-bytes 5242880 \
  --mode planning \
  --output engagement.json
```

### 2. Validate an Existing Engagement File

```bash
python3 -m cops engagement validate engagement.json
python3 -m cops engagement validate engagement.json --json
```

### 3. Compile an Immutable Action Plan

```bash
python3 -m cops engagement plan \
  --engagement engagement.json \
  --scenario COPS-E03.01-S01 \
  --target 10.0.0.10 \
  --specialist cops-pentest-specialist \
  --output action_plan.json
```

### 4. Inspect Engagement Summary

```bash
python3 -m cops engagement info engagement.json
```

## Python API

```python
from cops.engagement import (
    create_engagement_contract,
    validate_engagement_intake,
    build_action_plan,
)

# 1. Create and validate intake
eng = create_engagement_contract(
    name="Vulnerability Assessment",
    operator="analyst-01",
    included_targets=["10.0.0.10"],
    started_at="2026-10-05T00:00:00Z",
    authorized_until_utc="2026-10-05T12:00:00Z",
    mode="planning",
)

# 2. Compile reviewable ActionPlan
plan = build_action_plan(
    engagement=eng,
    scenario="COPS-E03.01-S01",
    target="10.0.0.10",
    specialist_id="cops-pentest-specialist",
)

print(f"Action plan generated: {plan.plan_id} (digest: {plan.plan_digest})")
print(f"Platform prerequisites: {plan.platform_prerequisites}")
print(f"Operations: {len(plan.operations)}")
```

## Error Codes and Guards

- `MissingOwnerError`: Operator/owner field was omitted or empty.
- `ScopeAmbiguityError`: Targets contain wildcards (`*`), overlapping exclusions, universal ranges, or empty/malformed values.
- `IncompatibleWindowError`: End time precedes start time or timestamps are invalid.
- `IncompleteBudgetError`: Budget duration or output bytes are not positive integers.
- `IncompleteLiveRequestError`: Live mode requested without mandatory budget, emergency contact, or safe mode constraints.
