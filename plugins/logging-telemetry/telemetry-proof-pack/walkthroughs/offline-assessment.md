# telemetry-proof-pack offline walkthrough

Correlate supplied synthetic marker records across emission, Cribl routing, destination indexing, and detection evaluation.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Trace synthetic markers across Cribl-to-Splunk and Cribl-to-Sentinel pipelines, demonstrating healthy, degraded, and broken pipeline classifications.

Working directory: `.`.

```text
python3 plugins/logging-telemetry/telemetry-proof-pack/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline-package-gate

Working directory: `.`.

```text
python3 plugins/logging-telemetry/telemetry-proof-pack/scripts/validate_package.py
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
git status --short -- plugins/logging-telemetry/telemetry-proof-pack
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Operates offline with recorded stage evidence; does not make live network calls to production Cribl Stream workers or SIEM APIs.
- Pipeline health reflects recorded evidence logs for synthetic markers and should not be confused with broad infrastructure telemetry uptime.
- Built-in redaction applies to Cribl metric details only; sanitize source exports and identifiers before use.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
