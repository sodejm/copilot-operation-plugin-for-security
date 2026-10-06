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
python3 -m cops lab run path/to/env.json path/to/action-plan.json path/to/authorization.json --case-type positive
```

## Python API

```python
from cops.laboratory import (
    LaboratoryHarness,
    make_inert_container_environment,
    make_inert_action_plan,
    make_inert_execution_authorization,
)

harness = LaboratoryHarness()
env = make_inert_container_environment()
verified_env = harness.verify_environment(env)

plan = make_inert_action_plan()
auth = make_inert_execution_authorization(plan)

result = harness.execute_case(
    environment=verified_env,
    action_plan=plan,
    authorization=auth,
    case_type="positive",
)
assert result.status == "success"
assert result.canary_verified is True
assert result.cleanup_receipt.status == "completed"
```
