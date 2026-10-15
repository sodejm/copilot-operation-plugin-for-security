# Threat Intelligence Enrichment operator playback

## Purpose and boundary

This playback exercises the production indicator normalization, approval,
provider parsing, retry, conflict, cache, and replay logic with injected responses.
It makes no socket calls, reads no credentials, and writes only the result chosen
by the operator. It does not validate provider authentication, current schemas,
licenses, rate limits, or the reputation of `example.org`.

Use the playback to learn the result contract and confirm deterministic local
behavior. Use an authorized test tenant separately before relying on a live
integration.

## Prerequisites

- A trusted repository checkout.
- Python 3.11 or newer.
- Bash or another shell that supports the commands below.
- A private, disposable output directory.

Run from the repository root:

```bash
P=plugins/detection-hunting/threat-intelligence-enrichment
COPS_TI_RUN=$(mktemp -d "${TMPDIR:-/tmp}/cops-ti.XXXXXX")
chmod 700 "$COPS_TI_RUN"
python3 "$P/scripts/validate_package.py"
python3 -m cops demo threat-intelligence-enrichment
python3 "$P/scripts/run_demo.py" > "$COPS_TI_RUN/result.json"
python3 -m json.tool "$COPS_TI_RUN/result.json" >/dev/null
```

## Expected result

Inspect `$COPS_TI_RUN/result.json`. These fields define a successful playback:

| Field | Expected meaning |
| --- | --- |
| `network_mode` | `injected-mock-only`; provider-shaped responses were supplied in memory. |
| `live_integrations_validated` | `false`; no live provider claim is made. |
| `request_attempts` | One MISP attempt, one TAXII attempt, and three Microsoft retry attempts. These are transport calls, not socket calls. |
| `misp.initial` | A positive result with conflicting malicious and contextual claims and their original restrictions. |
| `misp.fresh_cache` | A cache-only lookup before the ten-second positive TTL expires. |
| `misp.stale_cache` | An explicitly allowed stale lookup after expiry. |
| `misp.as_of_replay` | A historical selection at a time when the saved snapshot was fresh. |
| `taxii_partial` | `status: partial` and `error: pagination_limit`; the first page is retained without pretending the collection is complete. |
| `microsoft_failure` | `status: error` and `error: http_503` after the bounded retry sequence. |

The runner fails before printing JSON when any expected semantic condition is
missing. The validation command also checks the claim JSON Schema and the package
unit suite.

## Design and data flow

1. The runner creates one normalized domain indicator and source-scoped approvals.
2. An in-memory response sequence replaces the connector transport. The production
   `enrich` function still builds each bounded request and parses each provider
   response.
3. MISP attributes become source-specific claims. Opposing malicious/contextual
   assertions remain separate and populate `conflicts`.
4. The cache saves the complete result and exposes fresh, stale, and `as_of`
   reads without another provider attempt.
5. A TAXII `more: true` response becomes a partial result. Three Microsoft 503
   responses become a terminal provider error.
6. The runner assembles an outer playback envelope and checks the expected
   meanings with explicit exceptions before writing it to standard output.

## Contracts and validation

| Contract | Purpose | Key fields | Producer | Consumer | Definition | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Indicator | Identify the canonical lookup subject. | `kind`, normalized `value`, `digest` | `Indicator` | Approval, cache, provider routing | Runtime class in `threat_intel/core.py` | Unit tests cover normalization and rejected values. | Domain `example.org` and its SHA-256 digest. |
| Approval | Bind one approved source to one indicator lookup. | `source`, `indicator_digest`, `allow_sensitive` | Operator or caller | `enrich` | Frozen runtime dataclass in `threat_intel/core.py`; no standalone JSON Schema exists. | `enrich` rejects a mismatch before transport use. | Source `misp` and the demo indicator digest. |
| Source | Name a provider and its fixed request location. | `name`, `origin`, `path`, caller credential | Trusted configuration | Connector routing | Frozen runtime dataclass in `threat_intel/core.py`; no standalone JSON Schema exists. | Source-specific runtime checks and package tests. | MISP origin with `/attributes/restSearch`. |
| Claim | Preserve one source assertion and its handling context. | `source`, `indicator`, `assertion`, timestamps, `evidence`, `confidence`, sharing restrictions | Provider parser | Conflict analysis and downstream analysts | `schemas/claim.schema.json` | `validate_package.py` and parser tests validate produced claims. | MISP `malicious` claim with distribution `0`. |
| Enrichment result | Report the result, cache provenance, and bounded errors. | `status`, `claims`, `conflicts`, `cache`, optional `error` and `as_of` | `enrich` and `Cache` | Caller and playback | Runtime dictionary contract in `threat_intel/core.py`; no standalone result schema exists. | Package tests cover success, partial response, retry exhaustion, cache freshness, and replay. | TAXII partial result with `pagination_limit`. |
| Playback envelope | Separate boundary metadata, attempt counts, and scenarios. | `schema`, `network_mode`, `live_integrations_validated`, `request_attempts`, provider scenarios | `run_demo.py` | Operator or package demo command | Runner-owned JSON contract; no standalone JSON Schema exists. | Explicit runner checks and `tests/test_threat_intelligence_playback.py`, including optimized Python. | `cops.threat-intelligence-playback/v1`. |

## Reruns and failure paths

Rerunning the command should preserve the same semantic statuses, claims, cache
states, conflict set, and attempt counts. The demo uses a fixed synthetic clock
for provider and cache behavior. JSON key order and formatting are stable, but
do not use a byte-for-byte match as a substitute for inspecting meanings.

The expected TAXII and Microsoft failures are represented inside a successful
playback result. A nonzero command exit instead indicates a contract, import,
schema, or runtime failure. Keep standard error with the run record and do not
reinterpret an absent provider result as a clean reputation finding.

Common problems:

- `datetime.UTC` or syntax/import errors usually mean Python is older than 3.11.
- `No module named cops` means the command was not run from the repository root.
- A package validation dependency error requires the repository's documented
  development environment; do not bypass the schema or test gate.
- Different attempt counts indicate changed retry behavior and require review.

## Cleanup and limitations

Remove only the directory created for this run:

```bash
rm -rf "$COPS_TI_RUN"
unset COPS_TI_RUN P
```

The playback does not test DNS, TLS, redirects, actual provider authorization,
provider-side pagination, cooldown persistence, live schema drift, or durable
cache history. Injected mocks demonstrate local behavior only. A positive claim
is evidence attributed to its source, not an independent verdict.

<!-- BEGIN COPS GENERATED OFFLINE ASSESSMENT LINKS -->
## Generated offline assessment

- [Machine-readable playbook](../playbooks/offline-assessment.json)
- [Runnable offline walkthrough](../walkthroughs/offline-assessment.md)
<!-- END COPS GENERATED OFFLINE ASSESSMENT LINKS -->
