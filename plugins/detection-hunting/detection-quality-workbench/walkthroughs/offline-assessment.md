# detection-quality-workbench offline walkthrough

Validate Sentinel KQL and Splunk SPL detection rules against labeled positive, negative, and boundary telemetry fixtures.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Run offline quality evaluation of Microsoft Sentinel KQL and Splunk SPL rules against positive, negative, and schema-drift fixtures.

Working directory: `.`.

```text
python3 plugins/detection-hunting/detection-quality-workbench/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline-package-gate

Working directory: `.`.

```text
python3 plugins/detection-hunting/detection-quality-workbench/scripts/validate_package.py
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
git status --short -- plugins/detection-hunting/detection-quality-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Operates offline with a deterministic reference evaluator; does not prove actual live Kusto or Splunk indexer scheduling and alert firing.
- Precision and recall metrics are measured strictly on labeled test fixtures and must not be cited as production efficacy rates.
- Detection fixtures model event streams and boundary conditions; live pipeline ingest latencies require dedicated telemetry proof packs.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
