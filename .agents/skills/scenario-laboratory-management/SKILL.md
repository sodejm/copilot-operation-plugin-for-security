---
name: scenario-laboratory-management
description: Manage scenario laboratory environments with canary validation, isolation enforcement, reproducible reset, and verified case execution.
---

# Scenario Laboratory Management

Manage operator-controlled container and VM laboratory environments for offensive and defensive security operations. Enforces tested platform matrices, tool prerequisites, network and process isolation, canary verification, and reproducible resets with cleanup receipts.

## Core Responsibilities

1. **Environment Verification & Matrix Check**:
   - Verify operator VM/container environments against tested OS, runtime, and tool version matrices.
   - Enforce network isolation, egress restrictions, and canary token placement.
2. **Reproducible Baseline Reset**:
   - Execute deterministic rollback scripts or snapshot reverts to restore pristine verified states.
   - Confirm canary token presence post-reset.
3. **Controlled Case Execution**:
   - Enforce execution authorization, worker identity binding, and scope guard gates prior to launching scenario runs.
   - Execute positive, negative (controlled rejection), and remediated (defensive mitigation) cases.
   - Produce structured `RunResult` records and verified `CleanupReceipt` side-effect rollbacks.

## CLI Usage

### Check Tested Matrix

```bash
python3 -m cops lab matrix
```

### Register an Environment

```bash
python3 -m cops lab register path/to/env.json
```

### Verify Isolation and Canary

```bash
python3 -m cops lab verify path/to/env.json
```

### Reproducible Reset

```bash
python3 -m cops lab reset path/to/env.json
```

### Execute a Laboratory Case

```bash
python3 -m cops lab run \
  --environment path/to/env.json \
  --plan path/to/action-plan.json \
  --authorization path/to/authorization.json \
  --worker-inventory path/to/worker-inventory.json \
  --authorization-trust-store path/to/authorization-trust.json \
  --engagement path/to/engagement.json \
  --case-type positive
```

## Python API

```python
from cops.laboratory import (
    LaboratoryHarness,
    make_inert_container_environment,
    make_inert_action_plan,
    make_inert_engagement,
    make_inert_execution_authorization,
)
from cops.execution import (
    AuthorizationSigner,
    AuthorizationTrustStore,
    WorkerCapabilityInventory,
)

harness = LaboratoryHarness()
env = make_inert_container_environment()
verified_env = harness.verify_environment(env)

engagement = make_inert_engagement()
plan = make_inert_action_plan(engagement_id=engagement.engagement_id)
# Load this secret from the operator's secret store. The independently
# provisioned verifier trust store must contain the matching key identifier.
signer = AuthorizationSigner(
    key_id="lab-key-2026-10",
    operator=engagement.operator,
    secret=operator_signing_secret,
)
auth = make_inert_execution_authorization(
    plan,
    signer=signer,
    engagement=engagement,
    worker_identity=env.owner,
)
trust_store = AuthorizationTrustStore.from_file("path/to/authorization-trust.json")
inventory = WorkerCapabilityInventory.from_file(
    "path/to/worker-inventory.json",
    expected_worker_identity=env.owner,
)

result = harness.execute_case(
    environment=verified_env,
    action_plan=plan,
    authorization=auth,
    trust_store=trust_store,
    engagement=engagement,
    worker_inventory=inventory,
    case_type="positive",
)
assert result.status == "success"
assert result.canary_verified is True
assert result.cleanup_receipt.status == "completed"
```
