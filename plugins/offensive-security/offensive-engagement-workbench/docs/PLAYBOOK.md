# Operational Playbook: Offensive Engagement Workbench

## Overview

The Offensive Engagement Workbench guides security operators through the intake and planning lifecycle of authorized security testing engagements:

1. **Intake Authorization**: Collects and validates targets, exclusions, operator identity, assessment window, allowed effects, execution budget, and credential references.
2. **Boundary Gating**: Validates that no target is ambiguous (e.g. wildcards or universal CIDRs) or conflicts with excluded systems.
3. **Execution Mode Validation**:
   - `planning`: Purely passive/offline assessment modeling.
   - `import`: Ingests and reviews pre-existing scanner or log outputs.
   - `laboratory`: Runs synthetic simulations in isolated sandbox environments.
   - `live`: Active network testing; strictly requires operator confirmation, safe mode, and complete budgets.
4. **Action Plan Generation**: Produces immutable `ActionPlan` (`cops.action-plan/v1`) with:
   - Platform prerequisites (OS, container requirements, tooling).
   - Operation steps with expected evidence, anticipated side effects, and cleanup obligations.
   - Bounded execution limits.
   - SHA-256 integrity digest.

## Triad Specialist Handoffs

Bounded execution handoffs operate under a four-party Triad coordination model:
1. **Planner (`propose`)**: Emits `cops.specialist-handoff/v1` proposing task delegation to a routed specialist with required capabilities and initial material plan digest.
2. **Specialist (`accept`)**: Verifies profile capability coverage from `agents/registry.json`. Refuses tasks when required tools or skills are absent (`MissingCapabilityError`).
3. **Domain Skeptic (`review`)**: Scrutinizes candidate evidence envelopes and findings for contradictory observations (`ConflictingEvidenceError`) or unsubstantiated claims.
4. **Evidence Auditor (`audit`)**: Enforces scope and plan invariance (`AuthorizationExpansionError`). Any modification to targets, operations, versions, effects, or material digests requires formal operator re-approval (`MaterialPlanModifiedError`).

## Scenario Laboratory Management & Testing

When evaluating scenarios in isolated environments (`mode: "laboratory"`):
1. **Environment Verification**: Validate operator-provided VM or container contracts against the tested platform matrix (Linux/macOS, x86_64/arm64, container/VM runtimes) and verify minimum tool prerequisites (`kubectl >= 1.24.0`, `nmap >= 7.80`, etc.).
2. **Canary and Isolation Auditing**: Ensure non-empty canary token presence, active network isolation, and strict egress restrictions before advancing environment status to `verified`.
3. **Reproducible Baseline Reset**: Trigger automated rollback or recreate mechanisms (`reproducible: true`) to restore verified baselines and confirm canary integrity prior to running tests.
4. **Controlled Case Execution**:
   - Enforce cryptographic `cops.execution-authorization/v1` envelope consumption and worker identity binding.
   - Run **positive cases** to confirm attack paths and canary discovery within safe boundaries.
   - Run **remediated cases** to verify that defensive controls effectively mitigate or block techniques.
   - Run **negative cases** to ensure controlled rejection when prerequisites or scopes are invalid.
   - Emit verified `CleanupReceipt` records on completion.

## Capability & Package Workflow Diagnostics

Prior to orchestrating engagements or evaluating scenarios:
1. **Platform and Tooling Inspection**: Run `python3 -m cops diagnostics --tools` to inspect host platform compatibility and determine whether optional security tool prerequisites (`nmap`, `kubectl`, `kube-bench`, etc.) are installed or missing. Missing tools in offline planning do not cause false execution passes.
2. **Package Structure & Readiness**: Validate that each registered package maintains compliant manifests (`package.json`, `plugin.json`), documented playbooks, offline test scripts, and skills directories.
3. **Truth-in-Advertising Enforcement**: Ensure capability claims strictly adhere to demonstrated evidence and operational readiness modes (`planned`, `import`, `laboratory`, `live-validated`).

## Emergency Procedures

If live assessment causes operational disruption or exceeds budget limits:
1. Operator invokes emergency contact listed in `rules_of_engagement.emergency_contact`.
2. Execution worker aborts immediately and initiates side-effect rollback via `CleanupReceipt`.
3. Engagement status transitions to `aborted`.
