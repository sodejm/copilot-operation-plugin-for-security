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

For a disposable laboratory run, an owner may pass its content-addressed
`cops.laboratory-retest-evidence/v1` reference to
`verify_retest_execution_evidence_reference` with the authorization trust store,
verified endpoint inventory, observation trust store, engagement, exact finding
and asset identities, and a `TrustedLaboratoryContext` loaded independently of
the artifact. The context carries a verified disposable laboratory registration,
the trusted expected plan and target, and a provenance description naming their
trusted source. The verifier rejects unverified isolation, mismatched target or
plan, invalid attestation, observation or journal mismatch, and incomplete cleanup.
Supply a snapshot of previously consumed authorization IDs; existing entries are
rejected. This is a read-only prior-ledger assertion, not atomic replay prevention.
Concurrent reviewers need a separate durable transaction to record consumption.
Positive outcomes map
to `candidate_still_vulnerable`; accepted remediated outcomes map to
`candidate_fixed`; negative-control outcomes map to `blocked`, because a blocked
control does not prove remediation. This adds evidence for the normal offline
review and does not close findings. The journal binds the pre-execution
observation and cleanup reference, but current cleanup receipts do not provide a
workspace identity to bind.

Keep the input and outputs private and review them for sensitive identifiers
before sharing. If source authenticity or a target observation cannot be
verified, report an evidence gap instead of claiming a fix.
Executable laboratory retest review requires trust anchors obtained independently
of the evidence bundle: the protected terminal case-journal record digest, the
prior consumed-authorization ledger snapshot, and the owner-provisioned SSH
endpoint inventory. The endpoint inventory pins the complete connection identity
(host, port, SSH username, remote command, known-hosts pin, and supervisor
attestation key). Keep these sources protected and pass their independently
verified values to the verifier; pass the journal digest as
`trusted_terminal_journal_record_digest`. Values copied from the bundle are not
trust anchors. The verifier binds cleanup completion before the signed post-cleanup
operator observation. A verified bundle only creates a review candidate and never
closes a finding automatically.

The laboratory harness stages eligible review evidence in the terminal journal
before finalization. If artifact publication fails, restart with the same
protected journal and evidence store and call
`recover_retest_evidence_publication()`; this republishes the staged bundle
without rerunning the case or reusing its one-use authorization. Independent
review may happen later: durable verification checks the signed observation's
signature and chronology against the authenticated run, cleanup completion, and
terminal journal timestamp. Live classification still requires a fresh
observation.
