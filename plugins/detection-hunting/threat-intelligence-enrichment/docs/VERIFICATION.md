# COPS Threat Intelligence Enrichment: end-to-end verification

## Scope and prerequisites

Qualify local feed normalization, provenance/restriction handling, cache boundaries, and uncertainty. Historical fixture intelligence is not current reputation or independent verification of a threat.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info threat-intelligence-enrichment
python3 -m cops demo threat-intelligence-enrichment
python3 -m cops check threat-intelligence-enrichment
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/detection-hunting/threat-intelligence-enrichment
python3 "$P/scripts/run_demo.py"
```

Independently inspect the source MISP fixture and its original restrictions/timestamps before reviewing normalized output. The example.org claim is historical synthetic input and should require no network requests. Repeat the normalization/cache workflow described in the README using a sanitized local feed with independently annotated expected claims.

## Acceptance criteria

- Normalized claims retain source identity, original timestamps, evidence, and distribution/restriction constraints.
- Stale claims remain stale; a normalized assertion does not become verified maliciousness or current reputation.
- Package tests cover denied lookups/cache boundaries, missing provenance, malformed feeds, unsupported TAXII/pattern input, and stale evidence.
- The demo reports local/offline behavior with zero network requests. Unsupported enrichment stays explicit.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Use a copied feed with missing provenance or an unsupported pattern and inspect rejection/uncertainty. Verify a denied lookup does not bypass policy through a cache. Restore the valid feed, rerun, and confirm no provider request or private feed content escaped into retained evidence.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **threat-intelligence-enrichment** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Normalize this local historical intelligence feed, preserving provenance, timestamps, distribution restrictions, and unsupported patterns. Explain uncertainty and cache/lookup boundaries. Do not query providers or label an indicator currently malicious without evidence.

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
