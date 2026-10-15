# incident-response-sandbox offline walkthrough

Create expiring typed plans and rehearse incident actions against synthetic local fixtures only.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Exercise fresh-clock plan, dry-run, execution, replay and expiry rejection, and rollback against disposable synthetic state.

Working directory: `.`.

```text
python3 plugins/incident-response/incident-response-sandbox/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline sandbox behavior

Working directory: `.`.

```text
python3 plugins/incident-response/incident-response-sandbox/scripts/validate-package.py
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
git status --short -- plugins/incident-response/incident-response-sandbox
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Only synthetic local JSON fixture actions are executable; production integrations are unavailable.
- Approver identity and plan hash are self-recorded assertions, not approval attestation or immutable provenance.
- Concurrent mutation by untrusted local accounts is not supported; use private staging.
- Host installation and live incident response behavior have not been verified.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
