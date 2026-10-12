# COPS Detection Quality & Regression Workbench: end-to-end verification

## Scope and prerequisites

Qualify offline rule validation, labeled-fixture evaluation, quality findings, and regression reporting. The local reference evaluator does not execute production KQL/SPL or establish production detection rates.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info detection-quality-workbench
python3 -m cops demo detection-quality-workbench
python3 -m cops check detection-quality-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/detection-hunting/detection-quality-workbench
python3 "$P/scripts/run_demo.py"
```

Pair each rule under rules/ with its matching fixture file as described in the README. Before running, independently count expected matches/non-matches and list time-window, duplicate, missing-field, and schema-drift expectations. Compare every rule result and suite summary; repeat on a sanitized labeled event set.

## Acceptance criteria

- Every intended rule and fixture pair is evaluated, with no skipped case hidden by a suite summary.
- Observed matches, false positives/negatives, and rule findings match the independent labels, including boundary events and duplicates.
- Package tests exercise malformed rules, field/schema gaps, time boundaries, and regressions. Missing evidence remains explicit.
- Reports distinguish reference evaluation from engine execution and do not invent production precision, recall, or deployment success.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Use a private rule/fixture copy with a deliberate expected-match regression and confirm it is reported. Restore the correct copy and rerun the suite. Confirm no rule deployment or provider call occurred and the original rules/fixtures were unchanged; preserve reports and remove private copies.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **detection-quality-review** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Evaluate these offline rules against their labeled fixtures. Reconcile each expected match and regression, report schema/time-window limits, and suggest evidence-backed improvements. Do not deploy rules or infer production metrics.

Check discovery, referenced-file/script resolution, output against the CLI and
independent oracle, refusal/uncertainty behavior, and test-installation cleanup.
Record unavailable hosts as blocked and failed installation/invocation as failed.
The host exercise itself supplies no live-service or offensive-action authority.

## Record and promote

Follow [the shared qualification and status-update guide](https://sodejm.github.io/copilot-operation-plugin-for-security/plugin-verification.html)
to save a sanitized run record, apply every intervening maturity gate, and request
independent review. After acceptance, update package.json maturity and all public
status labels together, link the accepted record here and in the README, and run
the repository checks. Keep unsupported integrations and remaining gaps explicit.
No status changes automatically when these commands finish.
