---
name: engagement-specialist-handoffs
description: Pass structured tasks and evidence between planner, specialist, skeptic, and auditor with capability checks and authorization invariance.
---

# Engagement specialist handoffs

Coordinate structured task and evidence handoffs between Planner, Specialist, Skeptic, and Auditor in Triad workflows:

- **Structured Handoff Contracts**: Emits and validates `SpecialistHandoff` (`cops.specialist-handoff/v1`) contracts with traceable lifecycle transitions (`proposed` -> `accepted` -> `in_review` -> `completed` / `rejected`).
- **Capability Coverage Assurance**: Verifies the recipient's declared skills and required capabilities, resolves the selected workflow to a local `.agents/skills/<id>/SKILL.md` and a specialist capability in `catalog/capabilities.json`, and records the implementation digest at acceptance. Acceptance, skeptic review, and audit reject missing, mismatched, or changed targets.
- **Skeptic Evidence Verification**: Audits candidate evidence envelopes and findings for contradictory observations, invalid digests, or unsubstantiated claims.
- **Auditor Invariance Enforcement**: Compares candidate handoffs against the approved `ActionPlan`, requiring fresh operator approval whenever targets, operations, tools, effects, or material plan digests diverge.
- **Proposal vs Execution Distinction**: A proposal is inert, acceptance records a resolved workflow target, and `completed` means the handoff passed the skeptic and auditor checks. These transitions do not invoke a skill or prove an execution result.

## CLI Usage

### 1. Propose a Specialist Handoff

```bash
python3 -m cops engagement handoff propose \
  --engagement engagement.json \
  --plan action_plan.json \
  --task "Review the authorized network discovery plan" \
  --planner "secops-lead" \
  --specialist "cops-pentest-specialist" \
  --workflow-skill "network-active-discovery" \
  --capability "cops-pentest-specialist" \
  --output handoff_proposed.json
```

### 2. Specialist Accepts Handoff (Verifying Capabilities)

```bash
python3 -m cops engagement handoff accept \
  --handoff handoff_proposed.json \
  --specialist "cops-pentest-specialist" \
  --output handoff_accepted.json
```

### 3. Skeptic Reviews Candidate Evidence

```bash
python3 -m cops engagement handoff review \
  --handoff handoff_accepted.json \
  --skeptic "cops-threat-hunter" \
  --evidence "env-tls-001" "env-tls-002" \
  --output handoff_reviewed.json
```

### 4. Auditor Enforces Plan Bounds and Approves Handoff

```bash
python3 -m cops engagement handoff audit \
  --handoff handoff_reviewed.json \
  --plan action_plan.json \
  --auditor "cops-compliance-auditor" \
  --output handoff_approved.json
```

### 5. Orchestrate End-to-End Triad Workflow

```bash
python3 -m cops engagement handoff workflow \
  --engagement engagement.json \
  --plan action_plan.json \
  --task "Review the authorized network discovery plan" \
  --planner "secops-lead" \
  --specialist "cops-pentest-specialist" \
  --workflow-skill "network-active-discovery" \
  --capability "cops-pentest-specialist" \
  --output handoff_completed.json
```

## Python API

```python
from cops.routing.handoff import (
    propose_specialist_handoff,
    accept_specialist_handoff,
    review_with_skeptic,
    audit_and_approve_handoff,
    execute_triad_handoff_workflow,
)

# 1. Propose handoff from planner to specialist
handoff = propose_specialist_handoff(
    engagement=engagement_doc,
    action_plan=plan_doc,
    task_description="Review the authorized network discovery plan",
    sender_id="secops-lead",
    specialist_id="cops-pentest-specialist",
    workflow_skill_id="network-active-discovery",
    capability_id="cops-pentest-specialist",
)

# 2. Specialist validates capability match and accepts
accept_specialist_handoff(handoff, specialist_id="cops-pentest-specialist")

# 3. Skeptic validates evidence consistency
review_with_skeptic(
    handoff,
    skeptic_id="cops-threat-hunter",
    evidence_envelopes=[{"envelope_id": "env-001", "subject": "pod-1", "fact": "privileged"}],
)

# 4. Auditor verifies material plan invariance and marks complete
audit_and_approve_handoff(
    handoff,
    auditor_id="cops-compliance-auditor",
    approved_action_plan=plan_doc,
)
```
