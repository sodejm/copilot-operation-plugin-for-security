---
name: execution-authorization-review
description: Review and verify cryptographically bound execution authorization envelopes and reject obsolete checksum receipts.
---

# Execution authorization review

Review, issue, and verify cryptographically bound, operator-authenticated execution authorization envelopes (`cops.execution-authorization/v1`) for immutable action plans (`cops.action-plan/v1`).

## Core Responsibilities

1. **Reject Legacy Receipts for Execution**:
   - Legacy checksum receipts (`schema_version: 1.0` or `receipt_id`) are unkeyed historical records.
   - They MUST NOT authorize any new live or executable security operation.
2. **Enforce Descriptor-Bound Envelopes**:
   - Execution authorizations must bind the exact `action_plan_id`, `plan_digest`, `engagement_id`, `specialist_id`, `target`, `limits`, `operations_summary`, and `credential_references`.
   - Modifying any operation, flag, target, or limit invalidates the envelope.
3. **Validate Lifecycles and Atomic Consumption**:
   - Envelopes transition from `approved` to `consumed`, `revoked`, or `expired`.
   - Replay of an already-consumed authorization envelope is strictly rejected.

## CLI Usage

### Validate an Execution Authorization Contract

```bash
python3 -m cops contract validate path/to/auth-envelope.json --type execution_authorization
```

### Validate Authorization Lifecycle Transitions

```bash
python3 -m cops contract transition approved consumed --type execution_authorization
```

## Python API

```python
from cops.execution import (
    create_execution_authorization,
    verify_execution_authorization,
    consume_execution_authorization,
    AuthorizationError,
)

# 1. Create envelope from an ActionPlan
envelope = create_execution_authorization(
    action_plan=plan,
    operator="security-operator@corp.internal",
    valid_hours=4,
)

# 2. Verify prior to execution
verified_envelope = verify_execution_authorization(
    authorization=envelope,
    action_plan=plan,
    worker_identity="worker-linux-01",
)

# 3. Atomically consume envelope upon execution dispatch
consumed = consume_execution_authorization(
    verified_envelope,
    worker_identity="worker-linux-01",
)
```
