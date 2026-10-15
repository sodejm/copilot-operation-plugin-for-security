# offensive-engagement-workbench offline walkthrough

Authorized adversary engagement intake, scope boundary validation, and immutable execution planning.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Run the planning-only engagement playback through a local inert subprocess and write validated evidence artifacts without network requests.

Working directory: `.`.

```text
python3 plugins/offensive-security/offensive-engagement-workbench/scripts/demo.py --tool-version python3=3.11.9 --output-dir build/playbacks/offensive-engagement-workbench
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `['build/playbacks/offensive-engagement-workbench']`.

## 2. validation-1

offline package gate

Working directory: `.`.

```text
python3 plugins/offensive-security/offensive-engagement-workbench/scripts/validate-package.py
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

Remove only the declared generated destinations after reviewing their evidence:

- `build/playbacks/offensive-engagement-workbench`

Inspect package changes from the repository root:

```text
git status --short -- plugins/offensive-security/offensive-engagement-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Operator authorization and rules of engagement envelope are required before executing plans.
- Only non-destructive, bounded assessment actions are modeled.
- Active live execution is refused when assessment window, emergency contact, or budget limits are incomplete.
- Network egress is prohibited outside explicitly approved live execution scopes.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
