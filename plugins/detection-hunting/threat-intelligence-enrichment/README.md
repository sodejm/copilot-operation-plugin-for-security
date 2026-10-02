# COPS Threat Intelligence Enrichment

Issue #29. This read-only library validates analyst-selected IPs, domains, URLs,
SHA-256 hashes, certificate SHA-256 fingerprints, email addresses, and Azure
application IDs. Each outbound request requires an `Approval` for the exact
source and indicator digest. Paths and queries in URLs, email addresses, and
application IDs also require `allow_sensitive=True`.

The current adapters query MISP attributes, TAXII 2.1 collection objects, and
Microsoft Defender Threat Intelligence hosts for IPs and domains, and Microsoft
Graph service principals for Azure application IDs. The service principal claim
means only that the app ID was found in the tenant; it is not a threat verdict.
The Graph read requires `Application.Read.All`, while Defender Threat
Intelligence hosts require `ThreatIntelligence.Read.All` and the relevant
Defender Threat Intelligence licenses. TAXII
matches only exact simple STIX indicator patterns, including IPv6 addresses and
certificate SHA-256 hashes, and marks a paginated response
partial. MISP responses at the 1,000-row cap are partial. Claims retain source
provenance and supplied confidence; a Microsoft host record is not a verdict.

The library imports the repository's `cops.connectors` SDK. Install from this
repository or package that SDK explicitly with the plugin before standalone
distribution. Configure MISP/TAXII origins from trusted operator settings;
configuration is not accepted from analyzed data. Credentials are caller-provided
and never written to results. Requests are TLS only, fixed route, no redirect,
10 seconds and 1 MiB per attempt, with at most three attempts. Positive cache
defaults to one hour; negative cache defaults to five minutes. Cache entries
are in memory and stale values are returned only for an explicit cache-only read.

Offline tests: `PYTHONPATH=.:plugins/detection-hunting/threat-intelligence-enrichment python3 -m unittest discover -s plugins/detection-hunting/threat-intelligence-enrichment/tests`.
Live source permissions, licenses, retention, schema variants, and provider
response semantics are unverified; use an authorized test tenant before relying
on operational coverage.
