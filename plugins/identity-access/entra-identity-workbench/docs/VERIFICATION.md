# COPS Entra Identity Workbench: end-to-end verification

## Scope and prerequisites

Qualify manifest ingestion, identity graph construction, and offline role/permission analysis. The demo uses a historical as-of time; a fresh analysis must disclose stale evidence rather than silently refresh it.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info entra-identity-workbench
python3 -m cops demo entra-identity-workbench
python3 -m cops check entra-identity-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/identity-access/entra-identity-workbench
COPS_ENTRA_RUN=$(mktemp -d)
PYTHONPATH="$P" python3 -m entrawb.cli graph --manifest "$P/fixtures/tenants/contoso-corp/manifest.json" --output "$COPS_ENTRA_RUN/graph.json"
PYTHONPATH="$P" python3 -m entrawb.cli analyze --manifest "$P/fixtures/tenants/contoso-corp/manifest.json" --json --output "$COPS_ENTRA_RUN/analysis.json"
```

Inspect the manifest and exports first; independently list identity membership, permission/RBAC relationships, source hashes, and pagination/collection completeness. Compare graph and analysis JSON with that inventory. Compare fresh analysis with the historical demo, including expected freshness differences. Repeat with a sanitized tenant bundle.

## Acceptance criteria

- Object and tenant identities, source hashes, and relationship types remain bound to the manifest.
- Membership, role assignments, and effective-permission premises match the independent inventory; a role is not proof of an exploitable path.
- Stale, paginated, missing, and incomplete exports remain visible as uncertainty/coverage limits. No API call fills a gap silently.
- Package tests reject malformed bundles and exercise evidence/freshness/identity boundaries; unsupported live operations remain explicit.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Remove an export or invalidate its hash in a private bundle and record the failure. Restore the complete bundle and rerun with the same as-of assumptions. Confirm no Graph request or tenant modification occurred, retain sanitized artifacts, and remove the run-owned directory.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **entra-identity-analysis** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Analyze the supplied offline Entra manifest and graph. Explain role and permission relationships with source references, collection/freshness gaps, and unverified exploitation premises. Use no ambient tenant credentials or live Graph calls.

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
