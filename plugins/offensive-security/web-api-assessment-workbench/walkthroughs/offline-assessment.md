# web-api-assessment-workbench offline walkthrough

Import HTTP traffic and API schemas, model endpoints and isolated sessions, and execute bounded request replays.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Execute offline synthetic replay and inventory inspection across imported API schemas and traffic captures.

Working directory: `.`.

```text
python3 plugins/offensive-security/web-api-assessment-workbench/scripts/demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline package gate

Working directory: `.`.

```text
python3 plugins/offensive-security/web-api-assessment-workbench/scripts/validate-package.py
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
git status --short -- plugins/offensive-security/web-api-assessment-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Operates strictly under explicit destination allowlists and operational rate/request budgets.
- Credentials and session identifiers are tokenized and redacted with deterministic truncated SHA-256 hashes.
- Streaming binary WebSockets and Server-Sent Events (SSE) are modeled as unsupported features.
- Live target probing requires explicit interactive authorization and non-empty destination guard.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
