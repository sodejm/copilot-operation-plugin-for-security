# ad-assessment-workbench offline walkthrough

Offline scoped Active Directory inventory and evidence-linked candidate privilege-path analysis.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Analyze a synthetic two-forest AD graph with a protected identity, trust boundary, and partial host collection.

Working directory: `.`.

```text
python3 plugins/identity-access/ad-assessment-workbench/scripts/run_demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline-package-gate

Working directory: `.`.

```text
python3 plugins/identity-access/ad-assessment-workbench/scripts/validate_package.py
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
git status --short -- plugins/identity-access/ad-assessment-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Only accepts an approved, opaque, local JSON export; does not collect from AD, hosts, LDAP, or Kerberos.
- Observed relationships and candidate paths do not prove the privilege can be exercised or that exploitation is possible.
- Missing paths and incomplete collection never establish environmental absence or safety; host installation and live integration are unverified.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
