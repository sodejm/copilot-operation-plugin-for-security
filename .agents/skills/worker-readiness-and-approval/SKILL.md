---
name: worker-readiness-and-approval
description: Verify isolated execution worker readiness, enforce unprivileged boundaries, and manage the concurrency-safe approval store.
---

# Worker readiness and approval store

Verify the isolated execution worker runtime, process boundaries, unprivileged isolation, and manage the concurrency-safe SQLite approval store.

## Core Responsibilities

1. **Process Isolation & Unprivileged Execution**:
   - Verify unprivileged execution boundaries (fail-closed if executing as root / UID 0).
   - Enforce process isolation, timeouts, allowed tool whitelists, and ephemeral workspace cleanup.
2. **ACID-Compliant Approval Store**:
   - Backed by local, owner-only SQLite store with WAL mode.
   - Atomic consumption prevents race conditions or double-spending among concurrent worker nodes.
3. **Execution Truthfulness**:
   - Emits structured `cops.run-result/v1` records with cryptographic output digests, artifacts, and exit telemetry.

## CLI Usage

### Check Worker Readiness and Configuration

```bash
python3 -m cops worker status --worker-inventory path/to/worker-inventory.json
python3 -m cops worker status --worker-inventory path/to/worker-inventory.json --json
```

### Inspect the Approval Store

```bash
python3 -m cops worker store
python3 -m cops worker store --status approved --json
```

### Execute an Authorized Action Plan

```bash
python3 -m cops worker execute path/to/action-plan.json \
  --authorization path/to/authorization.json \
  --worker-inventory path/to/worker-inventory.json \
  --authorization-trust-store path/to/authorization-trust.json \
  --engagement path/to/engagement.json
```

## Python API

```python
from cops.execution import (
    ApprovalStore,
    AuthorizationTrustStore,
    IsolatedWorker,
    WorkerCapabilityInventory,
)

# 1. Initialize approval store
store = ApprovalStore("~/.cops/approvals.sqlite3")

# 2. Store pre-signed authorization envelope
store.store_authorization(auth_envelope)

# 3. Load independently provisioned verifier trust and measured worker
# capabilities from owner-only files.
trust_store = AuthorizationTrustStore.from_file("path/to/authorization-trust.json")
inventory = WorkerCapabilityInventory.from_file("path/to/worker-inventory.json")

# 4. Initialize the worker with the approved engagement boundary.
worker = IsolatedWorker(
    inventory,
    store=store,
    trust_store=trust_store,
    engagement=engagement,
)

# 5. Execute the exact signed plan. The store atomically binds consumption to
# the verified receipt payload before marking it consumed.
run_result = worker.execute_plan(action_plan, authorization=auth_envelope)
assert run_result.is_successful()
```
