# sentinel-hunt-workbench offline walkthrough

Author, adapt, render, and stress-test twelve defensive Microsoft hunting workflows with deterministic offline evidence.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Run the complete offline playback: render all supported hunts, evaluate H01/H02/H10 scenarios, and verify drift guards.

Working directory: `.`.

```text
python3 plugins/detection-hunting/sentinel-hunt-workbench/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

library contract

Working directory: `.`.

```text
python3 plugins/detection-hunting/sentinel-hunt-workbench/scripts/huntwb.py validate library
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 3. validation-2

deterministic stress suite

Working directory: `.`.

```text
python3 plugins/detection-hunting/sentinel-hunt-workbench/scripts/huntwb.py test library --seed 20260916
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 4. validation-3

generated adapter drift

Working directory: `.`.

```text
python3 plugins/detection-hunting/sentinel-hunt-workbench/scripts/huntwb.py verify-adapters
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
git status --short -- plugins/detection-hunting/sentinel-hunt-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- The reference evaluator is not a Kusto engine or a Microsoft Sentinel emulator.
- Tenant behavior, cost, latency, false-positive rates, host activation, and live integrations remain unverified.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
