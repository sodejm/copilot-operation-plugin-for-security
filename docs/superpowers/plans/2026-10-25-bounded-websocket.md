# Bounded WebSocket replay implementation plan

**Goal:** Deliver an approved, bounded RFC 6455 text subset without weakening HTTP compatibility or claiming isolated/production qualification.

**Architecture:** A focused standard-library framing/handshake module uses the existing pinned-address connector, absolute deadline and approval-mediated replay entry point. A separate versioned operation binds WebSocket budgets and payloads. Tests use disposable loopback services and signed, persisted one-use approvals.

**Spec:** `specs/web-api-inventory-replay.spec.md`, including explicit protocol, frame, byte, deadline and cleanup limits.

- [x] Verify the predecessor repair and freshly fetched base `6848fd97`; retain all intentional changes on new branch `codex/bounded-websocket-replay`.
- [x] Define the supported subset and compatibility constraints before implementation.
- [x] Encode failing preflight/transport/approval tests.
- [x] Implement framing, handshake and budget accounting in `cops/web_api/websocket.py`.
- [x] Integrate through owned snapshots, exact approval, pinned connection and deadline controls in `replay.py`; retain HTTP version 2 digest semantics.
- [x] Add disposable-service vulnerable/corrected, TLS, malformed input, budget, cancellation and cleanup tests and executable BDD.
- [x] Update affected operator, contributor, architecture, security and portable-runtime documentation; synchronize vendor runtime.
- [x] Run focused suites, mandatory acceptance and repository `make check`; preserve original checkout and record residual qualification gaps.

Review focus: malformed framing before allocation; control-frame floods; cross-session credentials; handshake substitution and redirects; slow DNS/TLS/frame cancellation; partial evidence after failure; receipt reuse; HTTP-only approval compatibility. No new third-party runtime dependency, arbitrary shell adapter, live CLI execution or provider deployment is authorized by this workstream.

## Validation and handoff

- Python 3.13.16 with declared contributor dependencies: **674 focused API/OpenAPI,
  BDD and package tests passed**, no skips; one expected negative TLS-policy
  deprecation warning.
- Mandatory local-service gate: **9/9 passed**, explicitly loopback-only and not
  isolation-qualified.
- Full `make check PYTHON=.venv/bin/python`: **passed in 320.048 seconds** with
  unchanged inputs during validation. All 25 package gates passed; full-suite
  platform exclusions remain exclusions, not native-host qualification.
- Standalone Python package gate without development dependencies: **passed**,
  zero network requests. A negative import-guard regression proves pytest,
  cryptography and jsonschema are not imported by the offline gate.
- Portable export of all 25 packages and the focused installed/exported playback
  suite: **passed** (3 focused tests). The initial full gate caught an out-of-package
  documentation link; the canonical guide now ships inside the package, with a
  root documentation entrypoint. The new guide and vendored protocol module are
  staged as intended export inventory entries; no commit or hosted write was made.
- Documentation, adapter and marketplace freshness, synchronized runtime,
  focused Ruff lint/format and diff checks: **passed** before the final
  documentation-only handoff update.

Full validation receipt: `validation-qvpm2u_m.json` in the private draft archive;
the failed portable-link run is retained separately, not represented as a pass.
See the packaged `docs/BOUNDED_WEBSOCKET_REPLAY.md` for the supported subset and
the separate `R-WEBSOCKET` pending human-review entry.

Changes remain local and uncommitted on `codex/bounded-websocket-replay` in the
existing API completion worktree; the predecessor repair is preserved. No original
draft files, unrelated branches or worktrees were removed. No live CLI, production
provider, independent approval administration, OS/network isolation, hosted CI,
release, deployment or issue #100 closure is claimed. Next action: review the exact
integrated diff before any requested commit/PR, then qualify the actual isolated
worker and approval-provider deployment separately.
