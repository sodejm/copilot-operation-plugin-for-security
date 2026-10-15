# COPS Threat Intelligence Enrichment

## Purpose and supported sources

This read-only library validates analyst-selected IPs, domains, URLs,
SHA-256 hashes, certificate SHA-256 fingerprints, email addresses, and Azure
application IDs. Each outbound request requires an `Approval` for the exact
source and indicator digest. Paths and queries in URLs, email addresses, and
application IDs, private or otherwise non-global IP addresses, and URLs with
non-global hosts also require `allow_sensitive=True`. Internationalized domain
names are converted to ASCII IDNA before the approval digest and lookup.

The current adapters query MISP attributes, TAXII 2.1 collection objects, and
Microsoft Defender Threat Intelligence hosts for IPs and domains, and Microsoft
Graph service principals for Azure application IDs. The service principal claim
means only that the app ID was found in the tenant; it is not a threat verdict.
The Graph read requires `Application.Read.All`, while Defender Threat
Intelligence hosts require `ThreatIntelligence.Read.All` and the relevant
Defender Threat Intelligence licenses. TAXII
matches only exact simple STIX indicator patterns, including IPv6 addresses and
certificate SHA-256 hashes, and marks a paginated response
partial. MISP responses at the 1,000-row cap are partial. Every claim follows
[`schemas/claim.schema.json`](schemas/claim.schema.json) and retains its retrieval
time, source locator, supplied confidence, and sharing restrictions. MISP
distribution values and TAXII object marking references are carried as provider
identifiers. Missing or malformed restrictions are `unknown`; consumers must
resolve provider markings before sharing. A Microsoft host record is not a verdict.

## Prerequisites and quick start

Run these commands from the repository root in an activated project environment
with Python 3.11 or newer. The demo injects fixed provider responses and does not
need credentials or network access.

```sh
python3 -m cops info threat-intelligence-enrichment
python3 -m cops demo threat-intelligence-enrichment
python3 -m cops check threat-intelligence-enrichment
```

## Design and data flow

The library imports the repository's `cops.connectors` SDK. Install from this
repository or package that SDK explicitly with the plugin before standalone
distribution. Configure MISP/TAXII origins from trusted operator settings;
configuration is not accepted from analyzed data. Credentials are caller-provided
and never written to results. Requests are TLS only, fixed route, no redirect,
10 seconds and 1 MiB per attempt, with at most three attempts. HTTP 429 and 503
responses with `Retry-After` stop retries and start a source-scoped cooldown.
The cooldown accepts delta seconds or an HTTP date, is capped at one day, and
uses 60 seconds for malformed headers.
Positive cache defaults to one hour; negative cache defaults to five minutes.
Cache entries and snapshot history are in memory. Stale values are returned only
for an explicit cache-only read or an `as_of` replay. Replay selects the latest
snapshot retrieved by that time, including expired claims with their original
provenance. The default history holds 100 snapshots per lookup key; evicted
history is reported as `history_unavailable`. History does not survive process
restart and should not be used as a durable audit record.

| Contract or artifact | Purpose | Key fields | Producer | Consumer | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- |
| Indicator approval | Bind one lookup to an exact source and normalized indicator | Source, indicator type, digest, sensitive-data permission | Analyst | Connector | Digest, source, type, and sensitive-value checks | Approved domain lookup against TAXII |
| Source response | Supply bounded provider data | Status, headers, body, source locator | Injected transport or authorized provider | Adapter | TLS route, redirect, timeout, retry, and size policy | Synthetic MISP attribute response |
| Normalized claim | Preserve a source assertion without turning it into a verdict | Indicator, source, retrieved time, confidence, restrictions | Adapter | Analyst and downstream consumer | Claim schema and source-specific parsing | Microsoft host record with unknown restrictions |
| Cache and history snapshot | Support explicit fresh, stale, and as-of reads | Lookup key, claim, retrieval and expiry times | Enrichment library | Later read or replay | TTL, bounded history, and source-scoped cooldown | Latest snapshot at an analyst-selected time |
| Playback summary | Qualify adapters, conflicts, caching, limits, and retry exhaustion | Source outcomes, claims, cache states, failure results | `scripts/run_demo.py` | Maintainer | Semantic assertions with a transport that forbids network access | Conflicting MISP and TAXII claims retained separately |

## Playback structure and result

The public playback:

1. injects fixed MISP, TAXII, and Microsoft responses through a transport that
   rejects any network attempt;
2. exercises an initial MISP lookup, fresh and stale cache reads, and an `as_of`
   replay;
3. walks a paginated TAXII result and retains its partial-result marker;
4. retries Microsoft responses through the configured limit and records the final
   HTTP 503 failure; and
5. asserts claim provenance, cache state, retry counts, redaction, and the offline
   boundary before printing one JSON document.

| Result field | Purpose |
| --- | --- |
| `schema` | Identifies the output as `cops.threat-intelligence-playback/v1`. |
| `network_mode` | Confirms the playback used the injected mock-only transport. |
| `live_integrations_validated` | Remains `false`; the playback does not qualify provider tenants or credentials. |
| `request_attempts` | Reports the bounded attempt count for each provider. |
| `misp_initial`, `misp_fresh`, `misp_stale`, `misp_as_of` | Show initial, cached, expired-cache, and historical-replay outcomes. |
| `taxii_partial` | Records that the synthetic paginated result is incomplete. |
| `microsoft_failure` | Preserves the terminal injected failure after retry exhaustion. |

Run the registered public entry point:

```sh
python3 -m cops demo threat-intelligence-enrichment
```

Use the package runner directly only when debugging the playback implementation:

```sh
python3 plugins/detection-hunting/threat-intelligence-enrichment/scripts/run_demo.py
```

Run the focused offline tests with:

```sh
PYTHONPATH=.:plugins/detection-hunting/threat-intelligence-enrichment \
  python3 -m unittest discover \
  -s plugins/detection-hunting/threat-intelligence-enrichment/tests
```

Live source permissions, licenses, retention, schema variants, and provider
response semantics are unverified; use an authorized test tenant before relying
on operational coverage. See the [operator playback](docs/PLAYBOOK.md) for the
contract definitions, expected fields, rerun procedure, and cleanup.

Follow the [end-to-end verification playbook](docs/VERIFICATION.md) to qualify this
package's documented workflow and prepare evidence for a maturity review.
