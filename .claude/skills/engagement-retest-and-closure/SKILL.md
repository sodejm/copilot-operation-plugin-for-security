---
name: engagement-retest-and-closure
description: Compare saved baseline and retest assessments, preserve uncertainty, and prepare evidence-gated closure review without executing an assessment.
---

# Engagement retest and closure

Use this workflow when the user asks whether an earlier finding was fixed or an
engagement can be closed. It performs an offline comparison and never closes a
finding, approves a plan, or runs an assessment.

1. Collect the original and later assessment reports for the same engagement,
   their plan IDs and authorization records, cleanup receipts, an owner reference,
   and an explicit outcome for each baseline finding and exact asset. Verify the
   source of these records independently. A changed asset needs an approved
   identity mapping and reassessment; do not infer that a different address is
   the same asset.
2. Build `cops.retest-input/v1` from the
   [contract and accepted example](../../../docs/ENGAGEMENT_REPORTING.md#retest-findings-and-review-closure).
   Link each `absent` or `present` outcome to new evidence on assessed retest
   coverage for the exact scenario and asset. Record inaccessible, blocked, and
   not assessed cases as such. Confirm cleanup in the worker or target
   environment; a receipt digest proves internal consistency, not cleanup.
3. Run `python3 -m cops engagement retest --input INPUT --json-output PRIVATE_JSON
   --markdown-output PRIVATE_MD`, then validate the saved JSON with
   `python3 -m cops contract validate --type retest_report --source-input INPUT PRIVATE_JSON`.
   This checks derivation from the supplied input, not source authenticity.
4. Review each candidate result, closure gate, and next action. The report
   always blocks closure until independent verification.
   Confirm ownership, evidence authenticity, plan binding, authorization, and
   cleanup independently. Every live retest needs run authority and cleanup
   binding verification, even if the plan ID is unchanged. A changed live plan
   needs fresh authorization unless a valid bound approval covers it.
   Record residual risk and unresolved artifacts before any human closure.

Keep the input and outputs private and review them for sensitive identifiers
before sharing. If source authenticity or a target observation cannot be
verified, report an evidence gap instead of claiming a fix.
