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
source confidence when supplied, observation and retrieval times, expiry,
provenance, and source sharing restrictions. Every claim has a retrieval time
and a sharing-restriction field. Missing or malformed provider restrictions are
explicitly unknown; consumers must resolve provider markings before sharing.
Unsupported indicator/provider pairs return an explicit unavailable state. Disagreement is
reported as a conflict without a combined reputation score.

Requests use the shared fixed-route HTTPS transport, small response and time
budgets, bounded retries, and no redirect. The default cache is one hour for
positive and five minutes for negative results. Cached expired values are
returned only with an explicit stale label. The in-memory cache retains bounded
positive and negative snapshots after expiry. An as-of replay is cache-only and
selects the latest snapshot retrieved no later than the requested time,
including expired claims and their original provenance. If bounded retention
removed the needed history, replay reports history unavailable. Provider errors
do not become negative intelligence. A provider rate limit stops immediate
retries and starts a source-scoped cooldown; the caller sees the remaining wait.

Internationalized domain names are canonicalized to ASCII IDNA before their
approval digest and provider lookup. Private or otherwise non-global IP
addresses, including URL hosts, require sensitive-data approval before lookup.

Offline scenarios verify privacy denial, conflicting source claims, stale and
negative caching, historical replay, restriction preservation, IDN and private
address handling, rate limits, retries, and unsupported source coverage. Live
permission, license, and tenant behavior require separate authorized verification.
