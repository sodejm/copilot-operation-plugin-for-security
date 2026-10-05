---
name: engagement-intake-and-planning
description: Ingest authorized engagement scope, validate targets and windows, and compile reviewable immutable action plans.
---

# Engagement intake and execution planning

1. **Intake and RoE Verification**:
   - Collect and validate assessment targets, exclusions, operator ownership, assessment window, allowed effects, budget, and credential references.
   - Refuse any request lacking explicit operator identity, valid future assessment window, or unambiguous target specifications.

2. **Scope Boundary Enforcement**:
   - Reject wildcards (`*`, universal ranges), malformed network representations, and collisions where a target is simultaneously included and excluded.
   - Restrict active live requests to bounded subnets (/24 or narrower).

3. **Execution Mode Distinction**:
   - Explicitly distinguish between:
     - `planning`: Purely offline hypothesis modeling and test plan assembly.
     - `import`: Static parsing and ingestion of external logs, scans, and manifests.
     - `laboratory`: Synthetic or containerized simulation in an isolated environment.
     - `live`: Active network verification against production or staging infrastructure.
   - For `live` mode, mandate explicit budgets, non-empty emergency contacts, and active windows; refuse incomplete live requests.

4. **Action Plan Compilation**:
   - Produce an immutable `ActionPlan` (`cops.action-plan/v1`) with:
     - Declared platform prerequisites (OS, container boundaries, required CLI tools).
     - Bounded operations with expected evidence receipts, anticipated side effects, and cleanup obligations.
     - Execution budget limits and credential references.
     - Canonical SHA-256 `plan_digest`.

5. **CLI Invocation**:
   ```bash
   python3 -m cops engagement create --name "Scope Review" --owner "operator" --targets "10.0.0.5" --start "2026-10-05T00:00:00Z" --until "2026-10-05T23:59:59Z"
   python3 -m cops engagement validate <path-to-engagement.json>
   python3 -m cops engagement plan --engagement <path-to-engagement.json> --scenario COPS-E03.01-S01 --target 10.0.0.5
   ```
