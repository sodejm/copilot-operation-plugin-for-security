# Web API inventory and replay

The workbench imports HAR 1.2, OpenAPI 3, Swagger 2, Postman collections, and
raw HTTP without changing their source documents. Live HTTP and GraphQL replay
is permitted only for requests represented by an immutable `ActionPlan`, after
the approval authority returns a matching receipt for the worker identity and
after the destination and resolved address pass scope checks. Preview produces
a redacted plan report and performs no I/O.

Source provenance hashes exact file or inline UTF-8 bytes, including whitespace;
mapping inputs use sorted, compact JSON. Inventories retain an opaque digest
reference, never a source path or inline document. Caller-supplied digests must
match the imported bytes. Ambiguous raw HTTP authorities are rejected.
Report serialization strips URL user information and redacts query values,
fragments and recognizable credentials in relative references and metadata.
Wire requests remain separate: approval digests bind their lossless content.

OpenAPI 3.0.3 and Swagger 2 imports reconstruct each operation from its
effective security and location. Operation-level `security` replaces root
security, including an empty array that makes the operation public. A
requirement object combines its named schemes with AND; requirement objects are
OR alternatives, and an empty object is an anonymous alternative. Only named,
referenced declarations are resolved. Unknown, malformed, or unrepresentable
referenced schemes fail closed without echoing attacker-controlled content.
Unused declarations and sensitive-looking parameters never add credentials.
When multiple authenticated OR alternatives cannot fit one endpoint, the
importer selects the first declared alternative and records the omitted
alternatives as unsupported instead of combining them.

Security-requirement scope arrays must be valid for the referenced scheme.
HTTP and API-key schemes accept only an empty array. OAuth scopes must be
declared by the referenced scheme; a non-empty OAuth scope requirement fails
closed because the current inventory cannot preserve required scopes through
replay. HTTP Basic and Bearer credentials use `Authorization`.

For OpenAPI 3, the first declared server at the narrowest applicable level is
selected in operation, path, then root order. Server-variable defaults are
resolved before validation. The selected server must be an absolute HTTPS URL
whose authority has a non-empty hostname and, when present, a syntactically
valid, in-range port. Relative URLs, unresolved variables, empty-host or
malformed-port authorities, user information, query strings, fragments, and
non-HTTPS schemes fail closed with content-free errors. If no server is
declared, the offline placeholder `https://api.target.local/` is used. For
Swagger 2, an
operation-level `schemes` declaration replaces the root declaration. The first
effective scheme is selected, HTTPS is required, an absent scheme defaults to
HTTPS, and `basePath` is applied to every operation path. An explicit host must
have a non-empty hostname and, when present, a syntactically valid, in-range
port; empty-host and malformed-port authorities fail closed with content-free
errors. An absent host uses the same placeholder authority. Server URL paths
and `basePath` are joined with operation paths by normalizing only their shared
boundary; a root operation path (`/`) keeps its terminal slash after a non-root
prefix. Operation-path keys are paths, not request targets: `?` and `#`
delimiters are rejected rather
than being reinterpreted during replay. Normalization-changing controls,
whitespace, and backslashes in server, host, base-path, or operation-path input
also fail closed. Endpoint identifiers remain stable when the effective host,
method, and path are unchanged.

Preview requests synthesize redacted Basic, Bearer, header API-key, or query
API-key placeholders only for the selected operation requirement. Public
operations do not receive credentials, and imported session metadata contains
only mechanisms used by an operation. Unsupported authentication cannot be
silently converted to another mechanism. Header API-key names must be valid
HTTP field names and must not name transport-controlled fields such as `Host`
or `Content-Length`. Header credential destinations collide case-insensitively;
query credential destinations are case-sensitive, so names such as `api_key`
and `API_KEY` remain distinct in one representable AND requirement.

Authorization assessment uses actual disposable loopback services. Each REST
and GraphQL object case records owner, other-user, and anonymous outcomes. A
vulnerable profile exposes the owner's object to the other user; a corrected
profile denies it. Rate-limit assessment records each response and requires
enough requests to reach the configured enforcement threshold. Missing
observations are reported as insufficient evidence rather than success.

WebSocket import metadata is preserved, but live WebSocket replay is not
implemented. Production approval-provider deployment validation is a separate
Linux integration concern; focused tests use the same consume-only approval
protocol with signed authorizations and a persisted one-use approval store. The
local test authority does not demonstrate a separately administered deployment.

Live replay plans use tool version 2 and bind each exact source request, the complete
session list, the effective request after isolated role-session credentials are
applied, the complete budget, and the complete destination allowlist. Any change
requires a new plan and approval. Invalid header framing, URL user information,
non-finite budgets and ambiguous session isolation are rejected before consumption.
HTTP error statuses remain observed responses; transport failure stops the batch
because the remote effect can be uncertain.
Execution copies caller-owned requests, sessions, destinations and budgets before
plan comparison, then uses only those owned snapshots for approval consumption,
resolution, transport and reporting.

The transport resolves each hop once, validates its addresses, and connects directly
to a validated numeric address. HTTPS retains the original hostname for certificate
verification and SNI and permits TLS 1.2 or newer only. Default TLS contexts set that
minimum explicitly. Caller-supplied contexts must require certificate and hostname
verification and a TLS 1.2-or-newer minimum; replay validates them at construction and
again before use without changing them. Environment proxies are ignored. Redirects require fresh scope
checks; HTTPS downgrade is refused. A cross-origin redirect may proceed only after a
standard method rewrite has removed the request body and content headers and when no
credential-bearing header remains. Session-provided headers and declared session
authentication header names are credential-bearing even when their names do not match
common credential patterns; redirects that retain either a body or credentials are refused,
and other caller or session headers are cleared before the cross-origin follow-up.
One monotonic deadline covers DNS, connection, TLS, headers and bounded body reads.
A DNS resolver may finish after cancellation, but cannot dispatch a late request.
