# API draft reconciliation and acceptance repair implementation plan

**Goal:** Preserve the unfinished #100 draft and make delivered authorization acceptance truthful before adding another replay protocol.

**Architecture:** Keep the current approval and transport boundaries. Preserve only a Boolean GraphQL object-access observation alongside the opaque response-body digest; never restore raw bodies to reports. Keep the portable package gate offline and require a separate local-service acceptance gate in repository validation.

**Tech stack:** Python 3.11+, standard-library runtime and gate orchestration, declared pytest development dependencies.

**Spec:** `specs/web-api-inventory-replay.spec.md`; `specs/features/web_api_inventory_replay.feature`.

## Global constraints

- Preserve the original dirty checkout and unrelated worktrees.
- Keep the scanner and plugin validator standard-library-only.
- No network or approval activity in preview or the offline package demo.
- Missing observations, unavailable isolation and unsupported protocols are not passes.
- No hosted changes, release or deployment are implied by this local implementation.

## Review focus

- A digest-only legacy report cannot reconstruct missing GraphQL observations.
- An arbitrary non-Boolean metadata value must not become authorization evidence.
- Partial data disclosure remains a failure even alongside a forbidden error.
- A skipped, empty or incomplete acceptance run must fail the new gate.
- Local-service acceptance must never claim network isolation or provider qualification.

## Task 1: Preserve and reconcile

- [x] Freshly fetch default branch and create a dedicated branch/worktree from `6848fd97a7620fae74566c0afb3d50ff35fb911d`.
- [x] Preserve all 22 dirty draft files, binary tracked patch, source status and per-file hashes in a private external archive; verify bytes and unchanged source state.
- [x] Compare each path with the baseline: 4 identical, 18 different, 0 absent upstream. Keep old files as historical draft evidence, not as a transplant candidate.

## Task 2: Repair GraphQL observation loss

Files: `cops/web_api/models.py`, `cops/web_api/assessment.py`, `tests/test_web_api_assessment_evidence.py`, package authorized-assessment tests and synchronized vendor runtime.

- [x] Reproduce: offline package check passes while corrected local GraphQL authorization acceptance fails.
- [x] Encode round-trip and failure regressions before implementation.
- [x] Derive a Boolean or unknown GraphQL object-access observation before body redaction. Validate metadata on both public boundaries and retain raw-body legacy compatibility.
- [x] Keep unknown legacy digest-only reports inconclusive; test malformed/truncated evidence and disclosure with denial errors.
- [x] Verify vulnerable/corrected/insufficient outcomes through real disposable loopback requests.

## Task 3: Require explicit local-service acceptance

Files: `scripts/check_web_api_acceptance.py`, `scripts/agent/check.py`, `Makefile`, gate tests and affected spec/verification/contributor docs.

- [x] Add an explicit `make check-web-api-acceptance` entrypoint using declared development dependencies.
- [x] Make repository `make check` require it without putting real-network tests into the offline package gate.
- [x] Require all named acceptance cases and reject child failure, skips, empty/malformed/missing reports, unavailable prerequisites and timeout.
- [x] Prove failures propagate through both the focused gate and repository aggregator.
- [x] Run narrow regression suites, runtime freshness, package check, docs/adapters/marketplaces and `make check`.

## Task 4: Safe cleanup and handoff

- [x] Verify the abandoned OpenCode worktree remains clean at the shared baseline and remove that worktree/branch without force.
- [x] Keep dirty or unique work; do not globally prune stale registrations or delete linearized correction branches by ancestry alone.
- [x] Record validation receipts, remaining #100 blockers and one safe resumption action in `docs/API_DRAFT_RECONCILIATION.md`.

## Remaining issue-sized work

The subsequent [bounded WebSocket workstream](2026-10-25-bounded-websocket.md)
implements the text subset locally while preserving this repair. Issue #100
remains open: the local laboratory is loopback-only, not an OS/network isolation
boundary, and production approval-provider qualification is still outstanding.
Do not mark #100 complete or treat offline/loopback results as proof of those
deployment guarantees.
