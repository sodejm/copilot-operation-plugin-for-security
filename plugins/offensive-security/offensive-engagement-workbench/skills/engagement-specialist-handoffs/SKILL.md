---
name: engagement-specialist-handoffs
description: Pass structured tasks and evidence between planner, specialist, skeptic, and auditor with capability checks and authorization invariance.
---

# Engagement specialist handoffs

Coordinate structured task and evidence handoffs between Planner, Specialist, Skeptic, and Auditor in Triad workflows:

- **Structured Handoff Contracts**: Emits and validates `SpecialistHandoff` (`cops.specialist-handoff/v1`) contracts with traceable lifecycle transitions (`proposed` -> `accepted` -> `in_review` -> `completed` / `rejected`).
- **Capability Coverage Assurance**: Verifies that the routed specialist profile declared in `agents/registry.json` possesses all required capabilities, skills, and tools before accepting a handoff.
- **Skeptic Evidence Verification**: Audits candidate evidence envelopes and findings for contradictory observations, invalid digests, or unsubstantiated claims.
- **Auditor Invariance Enforcement**: Compares candidate handoffs against the approved `ActionPlan`, requiring fresh operator approval whenever targets, operations, tools, effects, or material plan digests diverge.
- **Proposal vs Execution Distinction**: Isolates inert task proposals from accepted specialist handoffs and live execution results.

## CLI Usage

```bash
python3 -m cops engagement handoff workflow \
  --engagement engagement.json \
  --plan action_plan.json \
  --task "Execute Kubernetes cluster configuration and RBAC assessment" \
  --planner "secops-lead" \
  --output handoff_completed.json
```
