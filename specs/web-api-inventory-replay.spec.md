# Web API inventory and replay

The workbench imports HAR 1.2, OpenAPI 3, Swagger 2, Postman collections, and
raw HTTP without changing their source documents. Live HTTP and GraphQL replay
is permitted only for requests represented by an immutable `ActionPlan`, after
the approval authority returns a matching receipt for the worker identity and
after the destination and resolved address pass scope checks. Preview produces
a redacted plan report and performs no I/O.

Every HAR, OpenAPI/Swagger, Postman, and raw HTTP source is limited to 8 MiB
(8,388,608 bytes) before parsing. File inputs use a bounded binary read of at
most the limit plus one byte, including when the stream returns short reads.
Inline strings and compact, sorted mapping serialization obey the same
encoded-byte limit. An exact-limit input is accepted; an oversized or unreadable
input fails with a stable, content-free error that does not disclose the source
path. Imports never fetch or execute source content.

Saved inventories and replay reports, including documents passed to `inspect`,
use the same 8 MiB maximum-plus-one binary-read boundary before UTF-8 decoding or
JSON parsing. Inspection identifies the supported public model, validates it,
and serializes that validated model; it never echoes an unvalidated parsed
document. Oversized, unreadable, malformed, and unrecognized documents fail with
stable content-free errors.

Source provenance hashes exact accepted file or inline UTF-8 bytes, including
whitespace; mapping inputs use sorted, compact JSON. Inventories retain an
opaque digest reference, never a source path or inline document. Caller-supplied
digests must match the imported bytes. A single-source inventory continues to
use `provenance`. A merged inventory sets `provenance` to null and uses
`provenance_sources` to preserve every source record, including repeated formats
and duplicate sources. Its identity is a digest of the sorted multiset of
non-secret source IDs, source types, and content digests. The identity is
independent of ingestion order and timestamps, while duplicates remain
significant.

Each provenance record is validated when it crosses either deserialization or
serialization. `source_id` must be an opaque, non-secret identifier of 1 to 128
ASCII letters, digits, hyphens, or underscores and must start with a letter or
digit. `sha256` must be 64 lowercase hexadecimal characters, and `path_or_uri`
must equal `sha256:<sha256>`. `source_type`, timestamp, and an optional
`raw_record_ref` must use their documented safe forms. Unknown provenance fields,
path-like values, credential-bearing references, invalid or mismatched digests,
and direct object mutations fail with content-free errors. Records are never
silently dropped. Ambiguous raw HTTP authorities are rejected.
Inventory display names and imported-source labels are also validated on both
deserialization and serialization. They must be bounded, single-line labels and
cannot contain absolute POSIX or Windows paths, URL references, credential
assignments, or recognizable plaintext credentials. Importer-controlled OpenAPI
and Postman titles that do not satisfy this contract are replaced with their
format's non-secret default label before persistence.
Authentication mechanisms are validated on both boundaries, including after
direct object mutation. `is_redacted` must be the Boolean value `true`.
`credential_hash` is either empty for a credential-free declaration or a
canonical 64-character lowercase SHA-256 digest; it can never contain credential
material. Authentication type, location, and token name must use the supported,
bounded public forms. Invalid metadata fails with a stable, content-free error,
including when an invalid endpoint and session contain matching values.
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
replay. HTTP Basic and Bearer credentials use `Authorization`. HAR imports
retain `Authorization` as the authentication mechanism's header name rather
than the scheme name. Preview synthesis emits
`Authorization: Bearer <placeholder>` or
`Authorization: Basic <placeholder>` and never creates `Bearer` or `Basic`
header fields. The CLI does not read credentials from the environment. An
integration replacing placeholders should provide `COPS_WEB_API_BEARER_TOKEN`
as the token only, without the `Bearer ` prefix, and
`COPS_WEB_API_BASIC_CREDENTIALS_B64` as the base64-encoded RFC 7617
`username:password` payload only, without the `Basic ` prefix, and
`COPS_WEB_API_API_KEY_VALUE` as the exact header, query, or cookie value only.
When HAR observations use different authorization schemes for the same host,
method, and path, the inventory preserves them as separate endpoint variants.
Each variant produces its own preview request and session authentication binding,
with a stable, unique endpoint identity; mutually exclusive `Authorization`
schemes are never merged into one request.

Every newly imported endpoint with one supported authentication mechanism has
an explicit `session_id` that names its credential-free `SessionContext`.
The association is retained through serialization, multi-source merge, preview,
action-plan construction, and replay. Session and endpoint identifiers are
deterministically namespaced by source content and occurrence during merge, so
duplicate inputs and distinct inputs using the same authentication scheme do
not collide or share a guessed credential context. Merged identity remains a
digest of the source provenance multiset, independent of ingestion order and
timestamps. Raw HTTP and Postman imports create these bindings for Bearer,
Basic, and header or query API-key mechanisms, just as HAR and OpenAPI imports
do. A malformed, missing, conflicting, or ambiguous explicit association fails
closed with a content-free error. Legacy inventories without endpoint session
references remain compatible only when an authenticated endpoint has exactly
one unambiguous matching session; otherwise request synthesis fails closed.

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

Opaque response bodies remain digest-only in saved reports. Before redaction,
the response model derives an optional Boolean `graphql_object_access`
observation from the bounded GraphQL response: object data means access, while
an explicit null object with only FORBIDDEN/UNAUTHENTICATED error codes means
denial. Other 2xx bodies remain unknown. A partial object disclosure remains
access even alongside an error. Metadata must be Boolean when present; it is
not execution authority. Raw-body legacy responses remain assessable, but
digest-only legacy reports without an observation remain insufficient evidence.
The derived observation survives report round trips without preserving bodies,
error messages, object identifiers or other payload content.

The portable package gate remains offline and discovers only its standard-library
`test_workbench*.py` family, without importing pytest-only acceptance modules.
Repository `make check` additionally
requires a separate local-service acceptance gate and all its named cases.
Test failure, missing dependencies, no collection, missing required cases,
skipped cases, invalid reports and timeout fail that gate. Its passing result
qualifies loopback functionality only, never isolation or a production provider.

Bounded WebSocket replay is available through the approved Python integration,
not the offline CLI. It supports RFC 6455 version 13 over `ws` or `wss`, GET
handshakes without an HTTP body, and one unfragmented UTF-8 text reply per
explicitly approved text message. An empty message list performs handshake and
close only; it never invents a ping or application payload. Each request owns a
fresh socket and its isolated session headers; no cookie jar or connection pool
is shared. The handshake key and client masking keys use fresh random bytes.

The WebSocket operation is `cops.web_api.bounded-websocket-replayer` version 1,
action `replay_websocket_session`. Its approval binds all source/effective
messages, session credentials, destinations and complete budgets. HTTP-only
operations retain their existing version 2 identity and canonical budget digest.
New WebSocket byte limits do not change an HTTP-only approval's meaning.

`max_websocket_frames` counts all sent and received frames, including text,
ping, pong and close. Preflight requires at least two frames per submitted
message plus two for close. `max_websocket_message_bytes` defaults to 65,536
and permits 1 through 65,536 UTF-8 bytes per text frame.
`max_websocket_bytes` defaults to 1,048,576 and permits 1 through 1,048,576
aggregate encoded frame bytes in both directions, including headers and masking
keys. Known outbound frames and the minimum reply/close overhead must fit before
approval consumption or DNS. Incoming frame lengths are checked before payload
allocation/read. The response handshake is separately capped at 16,384 bytes,
and the encoded request handshake at 8,192 bytes. The existing request timeout
is one absolute deadline for DNS, TCP, TLS, handshake, pacing, frames and close;
rate_limit_rps also paces successive application text sends within that deadline.

The server handshake must be HTTP/1.1 101 with valid Upgrade, Connection and
Sec-WebSocket-Accept values. Duplicate/malformed headers, redirects, negotiated
extensions or subprotocols fail closed. Transport-controlled handshake headers
cannot be supplied through request/session headers. Response evidence retains
only allowlisted handshake fields, counters, a valid close code and opaque
message digests; it never retains raw messages, close reasons or arbitrary
server headers. Replies observed before failure remain partial evidence.

Server frames must be unmasked, FIN-set and RSV-clear, use canonical lengths,
and be text, close, ping or pong. Binary/continuation/reserved opcodes,
fragmentation, compression, invalid UTF-8, oversized controls, malformed close
payloads and invalid close codes fail closed. Pings receive masked pongs with
the same payload; unsolicited pongs count against budgets. After all expected
replies, the client sends close 1000 and requires the peer's valid close frame;
early close, unexpected application data or abnormal close never becomes a
successful completed replay. Failure, timeout or cancellation closes the owned
socket, stops the batch and requires a new approval before retry. Cancellation
before consumption creates no dispatch. A resolver may finish after cancellation
but cannot create a late connection. No cleanup frame may exceed an approved
budget. TLS, numeric-address pinning and scope checks are the same as HTTP;
proxies and WebSocket redirects are never used.
The runtime scope must also explicitly set `egress_allowed` to true; an included
target alone cannot override a disabled WebSocket egress policy.

Production approval-provider deployment validation is a separate
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

Preview, plan construction, offline replay, and authorized execution reject a
request batch that exceeds `max_requests`; they never select or report a truncated
prefix. This pre-execution budget rejection occurs before replay dispatch and report
construction. It is distinct from per-request destination rejections and runtime
request or response outcomes, which retain the order and coverage of every request
in an accepted batch.

Every destination allowlist item is validated before preview, plan construction,
offline replay, or authorized execution can retain or report the allowlist. An item
must be an exact ASCII DNS hostname or canonical dotted-decimal IPv4 address, either
optionally followed by a decimal port from 1 through 65535, or a bracketed numeric
IPv6 address with an optional port. Legacy integer, hexadecimal, octal, and shortened
numeric IPv4 spellings are invalid rather than treated as DNS names. A wildcard is
supported only as `*.` followed by an ASCII DNS domain, has no port, and matches both
the domain apex and its subdomains. DNS name matching is case-insensitive. Schemes,
user information, paths, queries, fragments, percent encoding, surrounding or
embedded whitespace and control characters, empty or non-string values, invalid
ports, unbracketed IPv6, and other wildcard positions are invalid. The complete
allowlist fails closed if any item is invalid, including an unused item. Validation
performs no name resolution, takes a shallow snapshot without copying allowlist
elements, does not change caller-owned input, and does not include a rejected value
in an error, report, or formatted exception chain.

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
