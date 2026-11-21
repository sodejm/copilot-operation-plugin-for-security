# Engagement foundation reconciliation

This note reconciles the four closed foundation children of issue #64 with the
current repository contracts. It records local, source-derived evidence only;
it is not a claim of host installation, laboratory isolation, operator approval,
live-provider qualification, release, or deployment.

## Merged child evidence

| Child | Merged revision | Delivered boundary | Local contract evidence |
| --- | --- | --- | --- |
| #88 — intake and planning | `61060a47` | Validated Engagement intake and deterministic ActionPlan construction. | `tests/test_engagement_planning.py` exercises the planning contracts; planning does not grant execution authority. |
| #89 — specialist routing | `d642601f` | Typed specialist handoffs and deterministic routing artifacts. | `tests/test_specialist_handoff.py` checks the handoff contracts; a handoff is a proposal, not an approval or worker launch. |
| #90 — scenario laboratory | `d53fad23` | Laboratory environment, case, cleanup, and fixture-harness contracts. | `tests/test_laboratory_harness.py` checks the bounded harness and cleanup records; a local contract test does not establish host isolation or independent observation. |
| #91 — package diagnostics | `be5cd0b6` | Offline package validation and capability diagnostics. | `tests/test_capability_diagnostics.py` and the package gate validate declared, offline capabilities; they do not install a host package or exercise a live integration. |

The reconciliation also exercised the shared schema, approval-binding, evidence,
and reporting boundaries in `tests/test_contracts.py`,
`tests/test_authenticated_plan_security.py`,
`tests/test_credential_evidence.py`, and
`tests/test_engagement_reporting.py`.

## Accepted local boundary

The current local evidence establishes that the repository can validate the
contracts and offline package metadata listed above. The workbench's deterministic
playback remains inert: its package gate reports zero network requests. The
reporting workflow is likewise an offline join and renderer; it preserves
inconclusive states rather than promoting them to successful assessment claims.
See [Offline engagement assessment reports](ENGAGEMENT_REPORTING.md) for its
evidence-strength and caller-text redaction limits.

An ActionPlan remains distinct from execution authority. A worker may accept a
plan only after independent validation of a signed authorization bound to the
full plan, engagement, and expected worker, with atomic consumption. See
[Authenticated Execution](AUTHENTICATED_EXECUTION.md) for the operational trust
boundary and the evidence that repository tests cannot supply.

## Evidence still required

The following acceptance evidence remains outside this local reconciliation:

- An operator-authorized, disposable native-host run demonstrating the selected
  profile, identity binding, observed egress behavior, bounded results, denied
  out-of-scope channels, and cleanup.
- Observation from an independently administered trust boundary; same-process
  or same-host repository checks are not independent evidence.
- Installed-host acceptance for the applicable platform and host integration.
- Independent review of any operator approval, source authenticity, and retained
  external evidence before it supports an operational claim.

The next dependency is the separately authorized native-host and independent
observer qualification work; until it is complete, the foundation is limited to
the local contract and offline package evidence stated here.
