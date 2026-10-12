# COPS Offensive Engagement Workbench: end-to-end verification

## Scope and prerequisites

Qualify offline engagement intake, scope/prerequisite checks, immutable action planning, and specialist handoff. This workflow depends on the repository SDK; a valid proposal still requires execution approval.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info offensive-engagement-workbench
python3 -m cops demo offensive-engagement-workbench
python3 -m cops check offensive-engagement-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/offensive-security/offensive-engagement-workbench
python3 "$P/scripts/demo.py" --tool-version python3=3.11.9
```

The tool version argument matches the synthetic fixture's pinned metadata; record the actual Python version separately. Independently inspect engagement scope, targets, tools/versions, limits, and validity windows. Compare the plan/handoff with those facts. Repeat with a sanitized engagement and independently prepared scope/prerequisite oracle.

## Acceptance criteria

- Intake and handoff preserve engagement, specialist, action, target, time, tool/version, and evidence bindings.
- The action plan is immutable and its digest agrees across handoffs; valid planning remains approval-required and performs no operation.
- Package tests reject missing tools, stale windows, scope expansion, incompatible prerequisites, and invalid approval/hash assumptions.
- Host installation resolves the repository SDK dependency explicitly. Offline success cannot establish worker readiness, signed approval, or live execution.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Repeat with a missing/mismatched tool version and out-of-scope target in private inputs; inspect the prerequisite/scope refusal with no dispatch. Restore the approved input and rerun. Confirm no external operation, target change, or credential creation occurred; retain sanitized plan/handoff evidence and remove private copies.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **engagement-intake-and-planning and engagement-specialist-handoffs** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Build an offline action proposal and specialist handoff from this synthetic engagement. Verify scope, windows, tool versions, prerequisites, and plan digest. Keep execution approval pending and do not dispatch an operation.

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
