# Shared evidence SDK v1

Issue #25. Repository tooling, Python 3.11+, standard-library runtime. Existing
portable plugins and their public formats retain their independent contracts.

## Evidence

`cops.evidence/v1` requires acquisition and record IDs, source product/API/tenant,
explicit scope and region (or an unknown reason), source identity and locator,
observed/emitted timestamps (or explicit unknown reasons), acquired/transformed
UTC timestamps, request fingerprint, page number, normalization/redaction metadata,
sensitivity, canonical SHA-256 content hash, parent IDs and optional raw references.
Raw references use opaque store IDs and hashes, never URLs or raw payloads.
Record IDs bind tenant/scope, source identity/version and normalized payload hash.
Records with changed content are distinct; exact duplicates do not create records.
UTF-8 sorted JSON rejects duplicate keys, non-finite numbers, excessive depth/size,
unsupported versions and unknown fields. Hashes establish comparison, not trust.

`cops.acquisition/v1` receipts describe scope, interval, configured limits, consumed
budgets, generation, consistency and complete/partial/unknown status with reason
codes. Completion means exhaustion of the authorized query, not tenant coverage.
Terminal checkpoints persist the acquisition finish time atomically; later exports
and resumes preserve that interval. Caller-owned raw references are detached before
hashing, as are normalized payloads.
Observation freshness is fresh/stale/unknown using an explicit assessment time;
unknown observation times never inherit acquisition time. Reports omit payloads.
Assessment validates the full receipt and joins it by acquisition ID, tenant,
scope and request fingerprint before making completeness claims.

## Acquisition and trust boundaries

The runner owns positive finite page, attempt, record, response, aggregate byte,
normalized storage, depth, request timeout and active time bounds. Retries and
failed/duplicate pages consume budgets. Requests are reserved durably before
dispatch. Active time is checked between decoding, projection and record operations,
including duplicates; adapters yield projections incrementally so a large page
cannot defer the budget check until all records have been processed. Requests
interrupted after reservation retain conservative byte/time costs. Resume
cannot loosen bounds or change adapter/version, tenant, scope or request identity.
Tighter bounds must still cover consumed budgets and committed record size/depth.
Only page transactions advance cursors; accepted records and deduplication commit
atomically. Cursors are private, bounded and validated again before authentication.

Transport verifies TLS, disables redirects and compression, streams within a
monotonic deadline and byte cap, and validates exact origins/methods/paths before
obtaining ephemeral credentials. Cancellation closes the connection and disables
automatic reopening before credentials can be sent. No credentials enter
serializable plans, errors, envelopes or receipts. Error messages are fixed codes
without source exception text.
Projection omits unreviewed fields; redaction occurs before hashing. Private SQLite
storage is owner-only on POSIX; other platforms require caller-confirmed private
storage. It is not encrypted. The SDK trusts credential providers and adapters as
code, not arbitrary source response values. Dry runs use neither network nor auth.

## Adapters and failure behavior

Graph lists directory users with explicit ID/type fields, preserving opaque validated
next links and required headers. Ambiguous retry continuations stop partial.
Resource Graph runs a fixed resource query across explicit subscriptions, ordered
by ID, retaining skip tokens; truncation without a token is partial. Both use the
same runner and demonstrate atomic interruption/resume in fixtures. Log Analytics,
Sentinel, Splunk and Cribl examples are request plans only. Live permissions,
authentication, data residency and source consistency remain unverified offline.

Throttling honors bounded Retry-After/backoff. Authentication refresh is limited
to once per acquisition. Drift, expired cursors, cycles, exhausted budgets and
transport failures preserve accepted evidence and end partial. New collections
receive new acquisition IDs. No automatic raw-data storage, tenant actions or uploads.

## Acceptance evidence

Contract tests cover malformed provenance/timestamps/versions, canonical hashes,
tenant isolation and exact boundaries. Runner tests cover partial/throttled/auth
results, schema drift, duplicates, redaction, limits and hostile destinations.
Checkpoint tests inject failures before/after commits and during reserved requests.
Executable scenarios cover adapter resume, bounded partial results, secret-safe
dry runs and generic stale/incomplete assessment. Run focused tests and `make check`.
