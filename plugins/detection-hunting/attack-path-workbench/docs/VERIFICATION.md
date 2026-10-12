# COPS Attack Path Workbench: end-to-end verification

## Scope and prerequisites

Qualify imported-graph validation, bounded candidate-path analysis, remediation output, and read-only query intent. Candidate paths are analytical hypotheses, not demonstrated exploitation.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info attack-path-workbench
python3 -m cops demo attack-path-workbench
python3 -m cops check attack-path-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/detection-hunting/attack-path-workbench
COPS_PATH_RUN=$(mktemp -d)
python3 "$P/scripts/attackpath.py" analyze "$P/fixtures/illustrative/input.json" --output-dir "$COPS_PATH_RUN/report"
python3 "$P/scripts/attackpath.py" query-intent --start ILL-FINDING --target ILL-CROWN --scope ILL-SCOPE
```

The illustrative input is synthetic. Inspect report.md, report.json, graph.json, remediation-ledger.json, and completion.json in the output directory. Compare the graph edges, source references, candidate path, and remediation ledger with a reviewer-prepared graph. The query-intent result should remain blocked from live execution.

## Acceptance criteria

- Reports preserve scope, edge provenance, uncertainty, run identity, and artifact digests. Verify completion.json against the files it describes.
- Paths and remediation candidates agree with the independent graph; missing evidence never becomes a verified transition or exploit.
- Package checks cover malformed/provenance/scope inputs, traversal limits, and interrupted or failed output publication. Budget exhaustion stays partial and cannot prove a global minimum cut or absence of paths.
- Read-only query intent stays blocked without an implemented, authorized connector. No Azure/Graph request is attributed to this exercise.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Request the same report output directory again and inspect the refusal/overwrite contract before proceeding; never overwrite retained qualification evidence. Exercise the package's output-failure tests and inspect completion markers for partial/uncertain publication. Repeat in a fresh directory, verify source digests, and remove only the run-owned output.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **attack-path-assess and attack-path-review** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Analyze this illustrative graph with the deterministic workbench. Produce candidate paths and a remediation ledger with source references, scope and traversal limits. Review uncertainty and completeness. Do not execute query intents or exploit a path.

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
