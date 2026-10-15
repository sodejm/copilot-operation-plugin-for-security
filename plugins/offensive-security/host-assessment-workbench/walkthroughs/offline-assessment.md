# host-assessment-workbench offline walkthrough

Offline Linux and Windows evidence classification plus a bounded read-only native Windows bridge.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Classify synthetic Linux and Windows canary exports entirely offline.

Working directory: `.`.

```text
python3 plugins/offensive-security/host-assessment-workbench/scripts/demo.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

offline and native-contract package gate

Working directory: `.`.

```text
python3 plugins/offensive-security/host-assessment-workbench/scripts/validate-package.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 3. validation-2

playback semantics

Working directory: `.`.

```text
python3 plugins/offensive-security/host-assessment-workbench/tests/test_playback.py
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
git status --short -- plugins/offensive-security/host-assessment-workbench
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- The native Windows bridge reads bounded configuration, ACL, token, and protection metadata; it never performs a privilege crossing or changes assessed controls.
- Offline canary outcomes remain source assertions; the native receipt verifies only assessment-owned lifecycle cleanup and exact export binding.
- Imported identifiers must be synthetic or non-sensitive opaque IDs; do not provide raw credentials or paths.
- Native Windows integration remains unverified until the exact candidate revision passes the Windows hosted exercise.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
