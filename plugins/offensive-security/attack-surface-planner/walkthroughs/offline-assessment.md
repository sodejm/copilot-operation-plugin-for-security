# attack-surface-planner offline walkthrough

Reconcile approved Microsoft/Azure scope with pinned local exports and produce passive review plans.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Run the passive planning playback, including semantic rerun assertions and active-mode rejection.

Working directory: `.`.

```text
python3 plugins/offensive-security/attack-surface-planner/scripts/run_playback.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline package gate

Working directory: `.`.

```text
python3 plugins/offensive-security/attack-surface-planner/scripts/validate-package.py
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
git status --short -- plugins/offensive-security/attack-surface-planner
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Approval and ownership are operator assertions, not independently verified or cryptographically signed.
- Only the documented local JSON export profiles are supported; no live Azure, Entra, DNS, CT, or endpoint integration is exercised.
- Hypotheses do not establish exposure, exploitability, effective consent, or comprehensive inventory.
- Active methods are unavailable.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
