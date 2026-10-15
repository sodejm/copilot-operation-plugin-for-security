# threat-intelligence-enrichment offline walkthrough

Privacy-gated read-only enrichment with source-specific claims from MISP, TAXII, and Microsoft host data.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Exercise injected MISP, TAXII, and Microsoft responses, cache replay, conflicts, pagination, and provider failure without network access.

Working directory: `.`.

```text
python3 plugins/detection-hunting/threat-intelligence-enrichment/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline-unit-gate

Working directory: `.`.

```text
python3 plugins/detection-hunting/threat-intelligence-enrichment/scripts/validate_package.py
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
git status --short -- plugins/detection-hunting/threat-intelligence-enrichment
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Azure application IDs support only tenant service-principal lookup; this is not a threat verdict.
- TAXII complex STIX patterns and paginated collections are reported as incomplete.
- Standalone portable installation requires explicit packaging of the shared COPS connector SDK.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
