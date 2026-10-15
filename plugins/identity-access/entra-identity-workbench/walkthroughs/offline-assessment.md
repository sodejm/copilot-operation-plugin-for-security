# entra-identity-workbench offline walkthrough

Offline Entra ID, Azure RBAC, and AI Agent identity graph modeling, privilege analysis, and exposure review.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Run an offline analysis of a multi-principal Entra tenant with human, app, managed identity, and Agent ID relationships.

Working directory: `.`.

```text
python3 plugins/identity-access/entra-identity-workbench/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline-package-gate

Working directory: `.`.

```text
python3 plugins/identity-access/entra-identity-workbench/scripts/validate_package.py
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
git status --short -- plugins/identity-access/entra-identity-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Operates entirely on offline read-only tenant exports; does not perform live Microsoft Graph or Azure Resource Manager API calls.
- Graph paths establish structural entitlement reachability and privilege relationships; they do not prove active attacker exploitation.
- Requires tenant export manifests with explicit SHA-256 checksums; incomplete exports are flagged as unknown rather than asserted safe.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
