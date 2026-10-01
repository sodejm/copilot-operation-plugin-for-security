# Threat intelligence enrichment

Issue #29. Read-only enrichment of analyst-selected IP addresses, domains,
URLs, hashes, certificates, email addresses and Azure application IDs.

The input validator rejects malformed indicators and caps their length. Each
provider lookup needs a source-specific privacy decision before an outbound
request. URLs with paths, queries, user information, or fragments require an
explicit sensitive-data approval. The provider receives only the approved
indicator. No sample upload, detonation, or content fetching is supported.

MISP attribute search, TAXII 2.1 STIX indicator collection, and Microsoft
Defender Threat Intelligence host reads preserve source-specific claims,
source confidence when supplied, timestamps, expiry, and provenance. Unsupported
indicator/provider pairs return an explicit unavailable state. Disagreement is
reported as a conflict without a combined reputation score.

Requests use the shared fixed-route HTTPS transport, small response and time
budgets, bounded retries, and no redirect. The default cache is one hour for
positive and five minutes for negative results. Cached expired values are
returned only with an explicit stale label. Provider errors do not become
negative intelligence.

Offline scenarios verify privacy denial, conflicting source claims, stale and
negative caching, retries, and unsupported source coverage. Live permission,
license, and tenant behavior require separate authorized verification.
