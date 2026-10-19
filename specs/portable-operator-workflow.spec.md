# Specification: Portable operator workflow

## Purpose

The repository provides a single, catalog-driven operator entry point for every
cybersecurity package. A new analyst can discover capabilities, see evidence
boundaries, and run one safe offline example without knowing package-specific
commands. A contributor can validate the same package contracts and regenerate
host indexes from the canonical catalog.

## Acceptance criteria

1. `python3 -m cops doctor` verifies the local runtime and repository contract
   without downloading dependencies or contacting a service.
2. `python3 -m cops list` shows every cataloged package and independently reports
   offline workflow, host installation, and live integration support.
3. `python3 -m cops demo <plugin-id>` runs only the package-owned command declared
   in `package.json`, without a shell and with a bounded timeout.
4. `python3 -m cops check [plugin-id ...]` runs the deterministic checks declared
   by the selected package or every package when no ID is supplied.
5. Package commands using absolute paths, parent traversal, non-Python entry
   points, or files outside the package fail before execution.
6. `.agents/plugins/marketplace.json`, `.github/plugin/marketplace.json`, and
   `.claude-plugin/marketplace.json` are generated from `catalog/plugins.json` and
   drift causes validation to fail.
7. Every package has distinct Copilot, Codex, and Claude manifests whose ID and
   version match the canonical catalog; the Codex manifest also declares its
   required user-facing interface metadata.
8. Structural, offline, host-installation, and live-integration evidence remain
   separate. Repository checks never promote host or live support automatically.
9. The operator commands run on Python 3.11 or newer on Linux, macOS, and Windows.
10. Workflow discovery, validation, and unsigned fixture playback require only the
    standard library. Ed25519 evidence signing is available only when explicitly
    requested with the optional crypto extra; an unavailable signer dependency
    fails with a stable workflow error and does not produce signed evidence.
11. Resuming a persisted `planned` attempt reuses its exact plan, attempt number,
    and unconsumed authorization. A consumed attempt records the authority-issued
    authorization digest and exact authorization, action-plan, plan-digest,
    engagement, worker, and target bindings. Recovery advances such an attempt
    only when those fields reconcile with both the persisted plan and retained
    authority provenance; otherwise it fails closed without replaying approval.
12. A direct stage binding from an optional workflow input is valid only when the
    input has a typed default or the same stage has an `exists` condition on that
    exact input. Equality and inequality conditions do not guard absence.
13. Offline playback evaluates stage conditions before resolving bindings or
    invoking handlers. A false condition records a skipped stage without outputs
    or evidence, and unavailable dependencies or workflow outputs cannot be
    reported as successful completion.
14. Workflow actions declare whether retry is safe with an explicit boolean
    `action.idempotent`, which defaults to `false` and is bound into each compiled
    action plan and digest. A failed, partial, or interrupted non-idempotent action
    is terminal for that run after any required cleanup because execution may have
    produced side effects even when no result was recorded. Only an explicit
    `true` permits another attempt, with a fresh approval and the same logical
    idempotency key. The runtime does not infer safety from the tool name or retry
    count. A persisted, unconsumed `planned` attempt resumes its exact plan and
    approval without spending another attempt, including when `max_attempts` is
    one.
15. For compatibility, when an action omitted `idempotent`, a saved attempt may
    match the previous compiler's implicit-true plan. A multi-attempt legacy stage
    is authentic only when every saved plan matches that compiler and all receipt
    and artifact checks pass. Only its existing final `planned` attempt may run
    under the saved approval. After that attempt succeeds, fails, is partial, or
    is interrupted, later loads remain valid but cannot execute or consume another
    approval. Legacy recognition never grants retry permission to the action.
