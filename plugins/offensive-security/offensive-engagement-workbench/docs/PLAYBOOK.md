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

## Emergency Procedures

If live assessment causes operational disruption or exceeds budget limits:
1. Operator invokes emergency contact listed in `rules_of_engagement.emergency_contact`.
2. Execution worker aborts immediately and initiates side-effect rollback via `CleanupReceipt`.
3. Engagement status transitions to `aborted`.
