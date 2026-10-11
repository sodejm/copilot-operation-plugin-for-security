# Offline AD inventory and relationship analysis

The `ad-assessment-workbench` accepts one explicitly scoped, local JSON export. It
does not collect from AD, contact hosts, query LDAP/Kerberos, or authenticate. The
input enumerates allowed forests, domains, and hosts, collection records, nodes,
directed relationships, and start/goal queries. All IDs are stable, opaque labels;
names, credentials, and raw directory attributes are outside this contract.
The JSON document must have unique object fields at every level and a bounded
nesting depth. Invalid JSON, including duplicate fields or excessive nesting,
is rejected with `invalid_json`. UTC timestamps use `YYYY-MM-DDTHH:MM:SSZ` with
an optional one to six fractional digits before `Z`; other forms are rejected.

Each relationship names its collector, UTC collection time, completeness, and
whether it was observed or inferred. The analyzer rejects edges with missing
collectors, out-of-scope nodes, conflicting identities, unsupported relation
kinds, ambiguous cross-forest boundaries, or timestamps after their collection.
Only an explicit trust edge may cross forests. Collection records identify their
forest and optional domain/host; partial records never establish absence.
An edge attributed to a host collector must touch the scoped host as a node of
kind `host`; matching an ID on another node kind does not establish host evidence.

For every query, the analyzer returns bounded directed paths with edge evidence.
An observed edge is evidence of a reported relationship, not evidence that an
actor can exercise it. A path containing inference, partial collection, a
protected identity, or a trust boundary is flagged for validation. A missing
path is `not_found_in_collected_graph` only when the bounded search completes;
`search_incomplete` means a depth, path, or expansion limit stopped it, even if
candidate paths were found before the limit. Neither
status means safe or absent in the environment. Forest and host coverage are reported as `complete`, `partial`,
or `unknown` from the declared collectors. Forest coverage is complete only with
a complete forest-wide directory collection or a complete collection for each
scoped domain, and no partial directory records. The input and output are deterministic,
size bounded, and free of network calls.

Acceptance uses a synthetic, disconnected two-forest graph with an explicit
trust edge, a partial host collector, and a protected administrator. Negative
cases reject divergent duplicate identity IDs and cross-forest privilege edges.
Live collection and identity verification require a separately authorized
engagement and are outside this package's current support claim.
