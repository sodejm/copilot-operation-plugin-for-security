# COPS Telemetry-to-Detection Proof Pack: end-to-end verification

## Scope and prerequisites

Qualify offline route validation and stage-by-stage telemetry-to-detection proof. Ingestion or indexing evidence alone does not establish a rule match, alert, or complete delivery.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info telemetry-proof-pack
python3 -m cops demo telemetry-proof-pack
python3 -m cops check telemetry-proof-pack
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/logging-telemetry/telemetry-proof-pack
COPS_TELEMETRY_RUN=$(mktemp -d)
python3 "$P/proofpack/cli.py" validate --manifest "$P/fixtures/routes/cribl-splunk-route/manifest.json"
python3 "$P/proofpack/cli.py" trace --manifest "$P/fixtures/routes/cribl-splunk-route/manifest.json" --evidence-dir "$P/fixtures/routes/cribl-splunk-route" --json --output "$COPS_TELEMETRY_RUN/proof.json"
```

Independently map the manifest and evidence to each required route stage. Compare the healthy proof with the demo's healthy Splunk/Sentinel, indexed-but-rule-missed, missing-Cribl, and cross-tenant cases. Inspect the delayed-indexing and duplicate-marker fixtures through the README workflow, then repeat with a sanitized route bundle.

## Acceptance criteria

- Stage observations bind to the correct route, tenant, marker, and time window; input/source digests and missing coverage remain visible.
- Indexed-but-rule-missed is degraded, missing required stage evidence is broken/incomplete, and cross-tenant ambiguity stays unknown.
- Duplicate markers and delayed evidence do not create false complete delivery. Reconcile loaded evidence against an independent file inventory; warnings/skips are gaps.
- Package tests cover malformed manifests and stage/binding failures. Reports make no claim of live Cribl, Splunk, Sentinel, or alert execution.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Remove a required evidence stage in a private bundle and inspect the incomplete proof; restore it and repeat. Check delayed and duplicate cases without replacing their expected result with success. Confirm no route/provider mutation occurred, preserve sanitized proof, and remove private output.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **telemetry-proof-tracing** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Trace this offline telemetry route through every required stage. Preserve tenant/route/marker bindings and explain missing, delayed, duplicate, and rule-missed evidence. Do not infer an alert from indexing or query a live provider.

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
