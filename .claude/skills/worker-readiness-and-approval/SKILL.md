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
python3 -m cops worker status
python3 -m cops worker status --json
```

### Inspect the Approval Store

```bash
python3 -m cops worker store
python3 -m cops worker store --status approved --json
```

### Execute an Authorized Action Plan

```bash
python3 -m cops worker execute path/to/action-plan.json --authorization auth-12345678
```

## Python API

```python
from cops.execution import ApprovalStore, IsolatedWorker, WorkerConfig

# 1. Initialize approval store
store = ApprovalStore("~/.cops/approvals.sqlite3")

# 2. Store pre-signed authorization envelope
store.store_authorization(auth_envelope)

# 3. Initialize worker
worker = IsolatedWorker(WorkerConfig(worker_id="worker-linux-01"), store=store)

# 4. Execute action plan
run_result = worker.execute_plan(action_plan, authorization="auth-12345678")
assert run_result.is_successful()
```
