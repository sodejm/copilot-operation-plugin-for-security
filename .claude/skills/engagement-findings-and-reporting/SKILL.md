---
name: engagement-findings-and-reporting
description: Assemble and review an offline evidence-aware engagement assessment from local COPS contracts.
---

# Engagement findings and reporting

Use the [reporting guide](../../../docs/ENGAGEMENT_REPORTING.md) and
[specification](../../../specs/engagement-findings-and-reporting.spec.md).

1. Confirm the authorized Engagement scope and the source of every ActionPlan,
   RunResult, Finding and evidence envelope. Treat supplied modes, statuses and
   hashes as data, not proof of execution or authority.
2. Assemble a bounded `cops.assessment-input/v1` bundle in a private directory.
   Include explicit coverage for every result, access gap and planned assessment;
   record limitations and a context row for every Finding. Keep raw source
   payloads, credentials and artifact paths out of report prose.
3. Run `python3 -m cops engagement report --input INPUT --json-output JSON --markdown-output MARKDOWN`
   with new paths in that private directory. Validate the JSON with
   `python3 -m cops contract validate --type assessment_report JSON`.
4. Review scope and evidence joins, partial and contradictory results,
   reproducibility, sensitivity of free text, and both output files. Verify
   source authenticity and authorization through independent records before
   making those claims. Share only after a separate content review.

The command is offline and does not execute a scenario or prove complete
coverage. Missing access or evidence remains `not_assessed`.
