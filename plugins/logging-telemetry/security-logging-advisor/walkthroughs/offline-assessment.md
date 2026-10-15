# security-logging-advisor offline walkthrough

Inspect a local repository and guide cost-aware security logging recommendations from collected evidence.

This walkthrough uses only declared repository Python entrypoints. Review the
[operator playbook](../docs/PLAYBOOK.md) and the
[machine-readable playbook](../playbooks/offline-assessment.json) before running them.
The generator records commands as argv and does not execute them.

Run repository-root entrypoints from the repository root. Commands marked with the
package directory run from the exported package directory.

## 1. demo

Collect synthetic repository context, verify semantic reruns and partial-scan disclosure, and validate a human-authored recommendation template.

Working directory: `.`.

```text
python3 plugins/logging-telemetry/security-logging-advisor/scripts/run_playback.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 2. validation-1

package contract

Working directory: `.`.

```text
python3 plugins/logging-telemetry/security-logging-advisor/scripts/validate-plugin.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 3. validation-2

offline behavior

Working directory: `.`.

```text
python3 plugins/logging-telemetry/security-logging-advisor/scripts/test_plugin.py
```

Expected evidence:

- the declared command exits successfully.
- reported results are limited to the supplied offline fixtures and metadata.
- Expected durable writes: `[]`.

## 4. validation-3

playback regression

Working directory: `.`.

```text
python3 plugins/logging-telemetry/security-logging-advisor/scripts/test_playback.py
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
git status --short -- plugins/logging-telemetry/security-logging-advisor
```

Restore or delete only files created by the walkthrough. Do not reset unrelated work.

## Limits

- The scanner reports local repository signals; an analyst or agent must review them before making recommendations.
- CVE reachability report checks validate structure and evidence integrity only; semantic reachability and agent behavior require separate repository-specific review.
- No host installation is proven by the repository checks.
- Isolated laboratory execution is unverified unless separate run evidence says otherwise.
- These offline commands do not establish source authenticity or permission for live actions.
