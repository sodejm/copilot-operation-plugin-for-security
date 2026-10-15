# foundry-agent-harness offline walkthrough

Rehearse synthetic agent authorization and provider response handling with deterministic local fixtures.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Run six deterministic mock attacks through the authorization gate, verify semantic reruns, and exercise malformed-scenario rejection.

Working directory: `.`.

```text
python3 plugins/offensive-security/foundry-agent-harness/scripts/run_playback.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline-package-gate

Working directory: `.`.

```text
python3 plugins/offensive-security/foundry-agent-harness/scripts/validate_package.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 3. validation-2

playback regression

Working directory: `.`.

```text
python3 plugins/offensive-security/foundry-agent-harness/tests/test_playback.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## Corrected and insufficient paths

This package does not declare a separate corrected/insufficient fixture pair.
A successful demo or validation exit status is therefore structural or offline
evidence only; absence of that comparison is insufficient evidence of live
effectiveness, installation, or authorization.

## Cleanup and reset

The declared entrypoints have no durable output destination in their argv.

Inspect package changes from the repository root:

```text
git status --short -- plugins/offensive-security/foundry-agent-harness
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Runs bundled synthetic fixtures; does not connect to Microsoft Foundry, Semantic Kernel, a hosted model, a provider API, or a live MCP server.
- Provider-shaped responses and synthetic prices establish only local normalization, exact-binding, and budget-ledger behavior; they do not attest provider usage, billing, cancellation, or cleanup.
- Results establish only local fixture and gate behavior, not a real agent's prompt-injection resistance or production authorization posture.
- The MCP fixture uses subprocess isolation, not an operating-system network sandbox; use synthetic case data only.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
