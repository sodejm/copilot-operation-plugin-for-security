# COPS Host Assessment Workbench: end-to-end verification

## Scope and prerequisites

Qualify imported Linux privilege-boundary evidence and positive/negative/fixed canary interpretation. Imported canary assertions do not independently prove a live privilege crossing or cleanup; unfinished execution scope remains visible.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info host-assessment-workbench
python3 -m cops demo host-assessment-workbench
python3 -m cops check host-assessment-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/offensive-security/host-assessment-workbench
python3 "$P/scripts/assess.py" "$P/fixtures/synthetic/host_linux_positive_v1.json"
python3 "$P/scripts/demo.py"
```

Independently inspect the positive, negative, and fixed synthetic host evidence. Compare each assessment's source kinds, boundary premise, canary result, prerequisite status, and coverage with the fixture. Repeat with a sanitized imported evidence bundle and independent expected interpretation.

## Acceptance criteria

- The positive, negative, and fixed cases remain distinguishable and are labeled offline_import.
- Source kinds, prerequisites, missing coverage, and canary claims retain their supplied provenance; a fixture assertion is not an independently measured boundary crossing.
- The package gate validates declared structure and fixture behavior. Record unsupported/missing malformed-input, execution, and recovery coverage as qualification gaps rather than inventing tests.
- Pending local execution or Windows/live scope cannot be qualified by Linux imported fixtures.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Use an incomplete private evidence copy and verify rejection or an explicit coverage gap. Restore the complete copy and repeat. Confirm no elevated command or host mutation occurred. Inspect source digests and remove only private run-owned data; live canary cleanup needs separate measured evidence.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **host-linux-privilege-boundaries** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Assess these imported Linux positive, negative, and fixed canary fixtures. Explain privilege-boundary premises, supplied provenance, prerequisite/coverage gaps, and limits on live verification. Do not elevate privileges or claim independently observed cleanup.

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
