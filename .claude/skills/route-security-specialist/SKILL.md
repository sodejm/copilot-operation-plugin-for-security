---
name: route-security-specialist
description: Help choose a security workbench from an ordinary-language goal, such as planning an assessment, investigating a suspicious login, reviewing code, or deciding what to log.
---

# Route Security Specialist

Use this skill to identify, select, and route incoming security requests to the most qualified COPS specialist agent profile.

Start with the user’s goal. Routing and drafting do not require execution approval, a signed engagement, or a ready worker. Ask a short clarifying question when the goal could fit several workbenches.

## Model and effort preflight

Before implementing an issue, read the full scope and acceptance criteria and
assess whether specialized cybersecurity reasoning would materially help. Follow
the [model and effort guide](../../../docs/model-effort-routing.md): obtain a
fresh exact host catalog and the current model/effort, then run:

```bash
python3 -m cops route "<issue scope and acceptance criteria>" \
  --suggest-model --model-catalog model-catalog.json \
  --current-model <exact-host-model-id> --current-effort <supported-effort> --json
```

Review the inferred task and correct it with `--task-kind` or `--complexity` when
needed. Inspect `model_advice.current`, exclusions, and the recommendation. Pause
before implementation when the current pair is unverified or a change is
recommended. If a qualified Daybreak model would benefit the issue and requires
a change, suggest its exact model and supported effort before proceeding.
Otherwise verify that the current pair is adequate.

Apply a change only through supported host settings or an already authorized,
bounded subagent workflow that meets the launcher model-router and workboard
requirements. Verify the selected settings; a child override does not switch the
parent. The advisor does not launch agents, change settings, or grant access.
Blue and Red have separate access checks; unavailable access cannot be forced.
Keep `xhigh`, `max`, and `ultra` as explicit manual choices.

## Operational Workflow

1. **Analyze Incoming Intent & Context**:
   - Run the deterministic zero-token classifier:
     ```bash
     python3 -m cops.routing route "<request-or-task-description>"
     ```
     Add `--json` for structured automation pipelines.

2. **Evaluate Routing Decision**:
   - Review the selected profile, confidence score, and primary plugin.
   - If clarification is required, show the proposed purposes in plain language and ask what outcome the user wants. Do not select a specialist on their behalf.
   - For high-confidence matches, adopt the persona and operational charter defined in `agents/profiles/<specialist-id>.agent.md`.

3. **Handle Critical Tasks & Triad Orchestration**:
   - If the task or selected profile is `CRITICAL`, the router automatically outputs a **Triad Execution Plan**:
     - **Primary Specialist**: Authors initial analysis and candidate plans.
     - **Domain Skeptic**: Critiques assumptions and tests alternative benign hypotheses.
     - **Evidence Auditor**: Validates SHA-256 evidence envelopes and verifies authorization receipts.
   - Treat this as a proposed workflow. Drafts may identify missing evidence and approvals; follow the required Triad handoff before claiming validated deliverables or executing critical actions.

4. **Verify Interactive Authorization Gate**:
   - If `Interactive Auth: REQUIRED` is signaled (e.g. penetration testing, red team lateral movement, active containment), confirm operator authorization before consequential execution, not before routing or drafting:
     ```bash
     python3 -m cops.routing authorize --specialist <id> --action <action> --scope <target>
     ```
   - This specialist receipt does not replace exact-plan approval, worker readiness, scope enforcement, or other execution checks.
   - In interactive environments, prompt the human operator with explicit scope disclosures.
   - In non-interactive CI/CD runners, fail closed unless a pre-signed `AuthorizationReceipt` is supplied.

5. **Execute Deterministic Tooling**:
   - Delegate heavy data processing (parsing logs, calculating hashes, graph traversals, KQL rendering) to the designated standard-library Python scripts declared in the specialist's profile.
