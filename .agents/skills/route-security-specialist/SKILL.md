---
name: route-security-specialist
description: Automatically route security requests to the optimal specialist agent profile (penetration testing, red team, KQL, incident response, forensics, etc.) with Triad orchestration for critical tasks.
---

# Route Security Specialist

Use this skill to identify, select, and route incoming security requests to the most qualified COPS specialist agent profile.

## Operational Workflow

1. **Analyze Incoming Intent & Context**:
   - Run the deterministic zero-token classifier:
     ```bash
     python3 -m cops.routing route "<request-or-task-description>"
     ```
     Add `--json` for structured automation pipelines.

2. **Evaluate Routing Decision**:
   - Review the selected profile, confidence score, and primary plugin.
   - For high-confidence matches, adopt the persona and operational charter defined in `agents/profiles/<specialist-id>.agent.md`.

3. **Handle Critical Tasks & Triad Orchestration**:
   - If the task or selected profile is `CRITICAL`, the router automatically outputs a **Triad Execution Plan**:
     - **Primary Specialist**: Authors initial analysis and candidate plans.
     - **Domain Skeptic**: Critiques assumptions and tests alternative benign hypotheses.
     - **Evidence Auditor**: Validates SHA-256 evidence envelopes and verifies authorization receipts.
   - Adhere strictly to the generated 7-step Triad handoff sequence before finalizing deliverables.

4. **Verify Interactive Authorization Gate**:
   - If `Interactive Auth: REQUIRED` is signaled (e.g. penetration testing, red team lateral movement, active containment), confirm operator authorization:
     ```bash
     python3 -m cops.routing authorize --specialist <id> --action <action> --scope <target>
     ```
   - In interactive environments, prompt the human operator with explicit scope disclosures.
   - In non-interactive CI/CD runners, fail closed unless a pre-signed `AuthorizationReceipt` is supplied.

5. **Execute Deterministic Tooling**:
   - Delegate heavy data processing (parsing logs, calculating hashes, graph traversals, KQL rendering) to the designated standard-library Python scripts declared in the specialist's profile.
