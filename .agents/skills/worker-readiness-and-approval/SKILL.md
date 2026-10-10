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

Set `COPS_NMAP_SHA256` to the trusted, independently measured SHA-256 digest of
the approved Nmap executable. Repeat `--executable-sha256 TOOL=SHA256` for every
external adapter in the plan; `inert` needs no executable pin.

```bash
python3 -m cops worker execute path/to/action-plan.json \
  --authorization path/to/authorization.json \
  --worker-inventory path/to/worker-inventory.json \
  --authorization-trust-store path/to/authorization-trust.json \
  --engagement path/to/engagement.json \
  --executable-sha256 "nmap=$COPS_NMAP_SHA256"
```

## Python API

The production supervisor provisions the approval control, sandbox, and an
owner-only cleanup journal outside the execution workspace. See
`docs/WORKER_SUPERVISOR.md` for the complete configuration. An embedded worker
with those provisioned inputs must recover pending cleanup before accepting a
new plan:

```python
from cops.execution import IsolatedWorker

worker = IsolatedWorker(
    inventory,
    approval_control,
    sandbox,
    cleanup_journal_path=journal_path,
    expected_engagement_id=action_plan.engagement_id,
)
worker.recover_pending_cleanup()

run_result = worker.execute_plan(action_plan, authorization=authorization_id)
assert run_result.is_successful()
```
