# COPS Attack Surface Planner: end-to-end verification

## Scope and prerequisites

Qualify passive asset normalization and bounded assessment planning from local scope data. The synthetic workflow grants no scan authority; active assessment requires the separate execution contract.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info attack-surface-planner
python3 -m cops demo attack-surface-planner
python3 -m cops check attack-surface-planner
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/offensive-security/attack-surface-planner
python3 "$P/scripts/plan.py" "$P/fixtures/synthetic/scope.json"
```

Before running, independently list approved assets, exclusions, ports, time/authorization constraints, and conflicting source observations in the scope fixture. Compare the normalized inventory and proposed plan with that list. Repeat with a sanitized passive export and a scope allowlist supplied independently of that export.

## Acceptance criteria

- Every planned target and port fits approved scope; exclusions and source conflicts remain visible.
- Unknown or contradictory passive observations remain uncertain. A plan is not a scan result, an approval receipt, or proof of reachability.
- Package tests reject missing approval context, malformed ports, duplicate keys, unsafe paths/symlinks, and invalid hash bindings.
- All advertised protocol collectors and SDK-dependent execution paths have explicit prerequisites and separate evidence; this local plan does not qualify them.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

On private fixture copies, remove approval context and add an excluded target; confirm rejection or explicit quarantine with no dispatch. Restore the approved copy and repeat. Inspect output, input digests, and process state to confirm no network scan or target mutation occurred.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **authorized-attack-surface-planning** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Normalize these passive assets against the supplied approved scope and exclusions. Produce a bounded proposed assessment plan with conflicts, gaps, and execution prerequisites. Do not scan or treat the proposal as execution approval.

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
