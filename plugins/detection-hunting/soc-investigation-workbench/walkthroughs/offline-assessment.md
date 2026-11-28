# soc-investigation-workbench offline walkthrough

Plan and review bounded, evidence-backed SOC investigations without executing queries or response actions.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Run the complete malicious, benign, and insufficient-evidence investigation playback.

Working directory: `.`.

```text
python3 plugins/detection-hunting/soc-investigation-workbench/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

development package gate

Working directory: `.`.

```text
python3 plugins/detection-hunting/soc-investigation-workbench/scripts/validate-package.py
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
git status --short -- plugins/detection-hunting/soc-investigation-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- The local planner does not run security queries or response actions.
- Sentinel vendor integration and live service behavior require separate validation.
- Microsoft 365 acquisition requires the COPS shared evidence and connector SDK from this repository; standalone plugin installation does not include it.
- Microsoft 365 live integration and the remaining issue #27 sources are unverified.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
