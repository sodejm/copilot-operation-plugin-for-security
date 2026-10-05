---
name: scenario-laboratory-management
description: Manage scenario laboratory environments with canary validation, isolation enforcement, reproducible reset, and verified case execution.
---

# Scenario laboratory management

1. **Environment Verification & Matrix Check**:
   - Collect and validate operator-provided laboratory environments (VM or container).
   - Verify compatibility against the tested matrix of operating systems, distributions, container runtimes, and security tool versions (kubectl, kube-bench, kube-hunter, kubescape, nmap).
   - Reject mismatched prerequisites and environments lacking process or network isolation.

2. **Canary Validation**:
   - Confirm pre-seeded canary tokens and markers in authorized paths.
   - Guard against data leaks and ensure canary integrity before executing scenarios.

3. **Reproducible Baseline Reset**:
   - Execute deterministic container recreate or snapshot rollback workflows.
   - Re-verify canary placement post-reset and record the reset timestamp.

4. **Controlled Case Execution**:
   - Enforce cryptographic execution authorization envelopes and worker identity binding before executing any laboratory adapter.
   - Support positive, negative (controlled rejection), and remediated (defensive control mitigation) case execution.
   - Produce structured `RunResult` records and verified `CleanupReceipt` side-effect rollbacks.

5. **CLI Invocation**:
   ```bash
   python3 -m cops lab matrix
   python3 -m cops lab register <path-to-environment.json>
   python3 -m cops lab verify <path-to-environment.json>
   python3 -m cops lab reset <path-to-environment.json>
   python3 -m cops lab run <path-to-environment.json> <path-to-action-plan.json> <path-to-authorization.json> --case-type positive
   ```
