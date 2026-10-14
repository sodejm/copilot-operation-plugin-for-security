# COPS Sentinel Hunt Workbench: end-to-end verification

## Scope and prerequisites

Qualify hunt selection, explanation, compatibility assessment, parameter rendering, and local reference evaluation. Reference evaluation and an offline-qualified hunt do not establish execution in a Kusto engine.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info sentinel-hunt-workbench
python3 -m cops demo sentinel-hunt-workbench
python3 -m cops check sentinel-hunt-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/detection-hunting/sentinel-hunt-workbench
python3 "$P/scripts/huntwb.py" explain H01
python3 "$P/scripts/huntwb.py" compatibility H09
python3 "$P/scripts/huntwb.py" render H01 --surface sentinel_analytics --params "$P/examples/h01-parameters.json"
```

Review H01's fixture expectations before rendering it. Compare the rendered query and required tables/fields with the parameter file and compatibility output. The package gate runs the library, seeded reference evaluation, adapter checks, and workbench tests. Repeat on a representative sanitized event set with independently labeled matches and non-matches.

## Acceptance criteria

- The selected hunt, parameters, entity fields, time window, and output surface agree; required telemetry and incompatible surfaces are disclosed.
- Positive and negative fixture results match independently labeled expectations. Duplicate events, join multiplication, time boundaries, and missing fields do not create unsupported matches.
- Invalid parameters and unsupported adaptations are rejected or explicitly limited. Missing host schemas remain an installation/execution gap.
- The report labels local reference results correctly and makes no claim that a query ran in Sentinel, Defender, or another service.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Exercise an invalid parameter on a private copy of the example and record the rejection. Restore the valid parameter file and render again. Confirm rendering did not deploy a rule or mutate source fixtures. Retain the rendered-query digest; remove host test rules only if a separately authorized host test created them.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **plan-sentinel-hunt, author-sentinel-kql, and review-sentinel-hunt** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Explain H01, check its telemetry and surface compatibility, and render the supplied parameters for sentinel_analytics. Review the reference results and disclose engine/schema gaps. Do not deploy or run the query against a service.

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
