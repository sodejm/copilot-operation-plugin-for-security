# kubernetes-assessment-workbench offline walkthrough

Reconcile an approved Kubernetes context with a sanitized local observation and report identity and access limits.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Verify matching, limited-evidence, and rejected context-switch playbacks through the offline CLI.

Working directory: `.`.

```text
python3 plugins/offensive-security/kubernetes-assessment-workbench/scripts/demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline package gate

Working directory: `.`.

```text
python3 plugins/offensive-security/kubernetes-assessment-workbench/scripts/validate-package.py
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
git status --short -- plugins/offensive-security/kubernetes-assessment-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- Approval, context selection, cluster facts, and access observations are operator assertions, not independently verified.
- A Namespace UID is an object identity anchor and does not prove a universal cluster identity.
- No kubeconfig, kubectl, cluster API, node, control-plane, or admission-controller integration is exercised.
- The report never authorizes live execution or establishes security posture, exploitability, or complete coverage.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
