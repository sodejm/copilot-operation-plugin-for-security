# Shared evidence and connector SDK

The repository-owned `cops.evidence` and `cops.connectors` modules implement the
[v1 specification](../specs/shared-evidence-sdk.spec.md) using Python 3.11+ and
the standard library. They provide a common evidence contract and a bounded
acquisition lifecycle for reviewed, read-only adapters. Existing plugin evidence
formats remain independent; portable exports do not automatically include this SDK.
The Attack Path Workbench Azure profile explicitly distributes a generated,
allowlisted contract/validation subset without collector transport or authentication.
That subset also includes the local assessment export policy transformer and stream
redactor because its caller-provided provider, telemetry, and report assessment
adapters import them; it contains no provider transport, credential, or sink
integration.
`python3 scripts/agent/bundle_evidence.py --check` verifies this subset against the
canonical sources and is part of `make check`.

## Try the offline examples

From the repository root:

```bash
python3 -m cops.connectors.demo
```

The demo uses invented Microsoft Graph and Azure Resource Graph responses. Each
adapter commits one page, simulates termination, reopens its private checkpoint,
and collects the second page. It also reports a partial acquisition and a
synthetic stale observation through the same provider-independent assessment API.
It performs no credential lookup or network request and removes its temporary
checkpoints on exit. The [example directory](../examples/evidence-sdk/README.md)
also contains design-only request plans for Log Analytics, Sentinel, Splunk and
Cribl; those four plans are not executable connectors.

The same API can be exercised explicitly with fixtures:

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from cops.connectors import Checkpoint, Limits, collect, preview
from cops.connectors.demo import FixtureCredentials, FixtureTransport, offline_fixture
from cops.evidence import report

adapter, pages = offline_fixture("graph")
plan = preview(adapter)  # Initial request only; no auth or network.
with TemporaryDirectory() as directory:
    with Checkpoint(Path(directory) / "acquisition") as checkpoint:
        result = collect(
            adapter, checkpoint, FixtureCredentials(), FixtureTransport(pages),
            limits=Limits(pages=2, records=10),
        )
    assessment = report(
        result.records, result.receipt,
        as_of="2026-01-02T00:00:00Z", max_age_seconds=86400,
    )
```

For live use, omit the fixture transport and supply a reviewed credential provider.
Authorization for the tenant, query and storage is a caller responsibility. An
adapter's configured tenant is provenance supplied by that caller; the SDK does
not attest a token's tenant, audience, permissions or identity.

## Contracts, hashing and assessment

The machine-readable contracts are
[`evidence-envelope.schema.json`](../catalog/schemas/evidence-envelope.schema.json)
and [`acquisition-receipt.schema.json`](../catalog/schemas/acquisition-receipt.schema.json).
`validate_envelope` and `validate_receipt` additionally enforce cross-field
relationships, canonical hashes and configured size/depth bounds. Unknown fields
and unsupported schema versions fail closed. UTC timestamps use a trailing `Z`;
unavailable observed/emitted timestamps and source region use explicit unknown
reasons rather than invented values.

An envelope carries source product/API, tenant and scope, source identity/version
and locator, acquisition and transformation times, request fingerprint, page,
normalization/redaction metadata, sensitivity, parent IDs and an optional raw
reference. `record_id` hashes product, tenant, sorted scope, source identity/version
and normalized payload content. It stays stable across pages and acquisitions for
the same evidence. Changed payloads have different IDs. `content_hash` hashes the
whole envelope excluding that hash field, so provenance changes affect integrity.
Canonical JSON is sorted, compact UTF-8; duplicate keys, non-finite numbers,
excessive size/depth and non-JSON values are rejected. Hashes support comparison
and tamper detection against a trusted hash; they do not authenticate a source.

Receipts carry acquisition identity, generation, query fingerprint, tenant/scope,
interval, limits, consumed budgets and `complete`, `partial` or `unknown` status.
`complete` means the adapter exhausted this query. Source consistency remains
`unknown`, and query completion does not establish tenant coverage. `assess` and
`report` validate the full receipt and require matching acquisition ID, tenant,
scope and request fingerprint before using its completeness claim. Freshness is
`fresh`, `stale` or `unknown`, evaluated from an explicit observation timestamp,
assessment time and maximum age. Unknown or future observations remain unknown;
acquisition time never substitutes for observation time. Reports omit payloads,
but identifiers and aggregate results can still be sensitive.

## Normalization, redaction and raw preservation

Adapters project an explicit field allowlist before hashing or persisting records.
The included adapters omit names, mail, tags and other unselected response fields.
`build_envelope` detaches caller-owned payload and raw-reference structures and records
`projection/v1` and `omit-unselected-fields/v1` metadata. It does not discover or
remove arbitrary secrets: callers must supply a reviewed projection consistent
with those declarations. New normalization/redaction semantics need a coordinated
contract and adapter version change, with executable scenarios.

Keep original source data only when authorized and needed for reproducibility.
Raw storage is a separate caller-owned service with its own access, encryption,
residency, retention and deletion controls. The SDK neither saves raw responses nor
fetches raw references. An optional reference contains an opaque `store_id` and
SHA-256 hash, never a URL, credential or raw payload. Verify that hash when resolving
the reference outside the SDK. Parent IDs link derived evidence without embedding
its parents. Normalized evidence remains `restricted`; redaction does not make it
safe to publish automatically.

## Bounds and interruption recovery

`Limits` requires finite positive bounds for pages, attempts, records, response and
aggregate bytes, individual envelope size, normalized storage bytes, JSON depth,
request duration and total active time. Retries may be zero and otherwise remain
finite. Duplicate pages, failed requests and retry backoff consume budgets. Active
time is checked between decoding, adapter projection and record operations,
including deduplication. Adapters yield projections incrementally, and a time limit
preserves the record prefix accepted before it expired.
Oversized, malformed or compressed responses stop partial. Fixed-length responses
must reach their declared length. Provider error bodies are discarded; failures
expose fixed reason codes rather than source exception text.

The checkpoint durably reserves an attempt's response byte cap and duration before
dispatch. Successful requests settle known costs; interrupted dispatch or page
processing retains conservative reserved costs. Retry and credential-refresh
counters survive interruption. Accepted envelopes, deduplication IDs, page counters
and continuation state commit atomically. A crash before commit cannot advance the
cursor; a crash after commit resumes the next page. Repeated cursors end partial.

Resume uses the same checkpoint and adapter/version, tenant, scope and initial
request fingerprint. Limits can only tighten, and must still cover consumed
budgets and the size/depth of committed records. A terminal partial or complete
checkpoint exports its result without another request and preserves its original
collection finish time. To collect again, create a
new checkpoint directory and acquisition ID; increasing limits is not a resume.
Do not edit checkpoint state to bypass these bindings.

Use a trusted parent directory for checkpoints. On POSIX, the SDK requires an
owner-only directory and regular files, rejects symlinks and hard-linked files,
and holds an exclusive acquisition lock. New directories use mode `0700`, and
files use `0600`. SQLite transactions use a rollback journal with full synchronous
durability. The database is not encrypted, and it contains normalized evidence
and private continuation tokens. Other platforms require the caller to establish
private ACLs and pass `confirmed_private=True`; the SDK cannot verify those ACLs.
The storage budget counts encoded normalized envelopes, excluding SQLite, cursor
and filesystem overhead. Provision a separate disk quota when a physical storage
ceiling is required, and remove private checkpoints according to retention policy.

## Transport and credentials

`HttpsTransport` verifies TLS and permits only the adapter's exact HTTPS origin,
method and path. It does not follow redirects or decompress responses. Continuation
destinations are checked before every credential lookup. A credential provider
returns only an ephemeral `Authorization: Bearer ...` header; it must resolve and
refresh credentials without logging them. The runner refreshes once per
acquisition, applies bounded retry/backoff, and never serializes auth headers into
plans, envelopes, receipts or checkpoints. Keep credentials out of fixture and
provider exceptions too; fixed diagnostics are not a substitute for safe providers.

The built-in transport applies one deadline across connection, headers and body,
with socket cancellation and automatic reconnection disabled after the explicit
connection opens. An OS DNS resolver may remain blocked in a daemon
thread after the caller times out; cancellation prevents that delayed connection
from sending credentials. Credential providers, adapters and injected callbacks
are trusted code and must return promptly. Injected transports must enforce the
supplied timeout and response cap. Use caller-managed process isolation when
untrusted code or a hard process-lifetime ceiling must be enforced.

## Included adapter scope and live prerequisites

`GraphUsers(tenant)` reads `/v1.0/users`, requesting `id` and `userType` and
preserving validated opaque next links and required headers. It models directory
users only. Service principals, applications and Entra agent identities need
separate reviewed adapters and permission evidence. The application permission
listed by Microsoft for this operation is `User.Read.All`; consent and actual
token behavior require live verification. Ambiguous next links returned after a
retry end partial. See Microsoft's [list users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0)
and [paging guidance](https://learn.microsoft.com/en-us/graph/paging).

`ResourceGraph(tenant, subscriptions)` runs a fixed `Resources` projection of
`id`, `type` and `location`, ordered by ID across explicit subscriptions. It
preserves opaque skip tokens and stops partial on truncation without a token.
The conservative parser accepts a bounded ASCII resource ID subset; unfamiliar
shapes fail as schema drift. Resource Graph returns only resources readable by
the calling identity and can omit inaccessible resources without a signal. Read
RBAC, selected subscriptions and residency must be reviewed before live use. See
Microsoft's [Resource Graph overview](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)
and [Resources API](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2022-10-01).

Neither adapter infers an observation time from a fetch. Both fixtures leave it
unknown. Offline checks establish the local contract and failure behavior; live
permissions, schemas, authentication, consistency, latency and residency remain
unverified.

## Add a connector

1. Define a read-only query, explicit tenant/scope and field projection. Review
   permissions, identity, residency, raw-data need and source consistency.
2. Implement the `Adapter` protocol: identity/version, fixed origin/path/method,
   `request`, `validate_request` and `parse`. Requests must be credential-free;
   validate each continuation against an exact destination and query allowlist.
3. Return a `Page` with an iterable of projected payloads, yielding each projection
   as the runner consumes it so time checks can interrupt page processing. Include
   source identity, locator and accurate timestamps when available. Preserve opaque pagination without exposing it in
   reports. Mark truncation or uncertainty with a fixed reason code; never turn
   source text into a diagnostic.
4. Reuse `collect`, `Checkpoint`, `Limits` and the transport contract. Do not add
   a separate pagination/retry/auth lifecycle inside the adapter. Keep SDK runtime
   dependencies standard-library-only.
5. Add fixtures for interruption/resume, duplicates, drift, throttling, expired
   credentials/cursors, hostile continuations, redaction and exact budget bounds.
   Update the specification and executable scenarios before implementation when
   practical. Review source-derived identifiers and canary credentials in outputs.
6. Run focused tests and `make check`. Add live or host evidence separately before
   changing any integration claim.

Focused validation:

```bash
python3 -m pytest tests/test_evidence_contract.py tests/test_connector_sdk.py tests/test_evidence_transport.py tests/step_defs/test_shared_evidence_acquisition.py -q
make check
```

## Adoption and rollback

Adoption is opt-in. A portable plugin must declare and distribute a compatible SDK
dependency explicitly before importing it; the root module is not present merely
because the plugin was exported. Existing plugin formats need no migration for
this change. An incompatible envelope, normalization or checkpoint change requires
a new version and a new acquisition, not an in-place rewrite of collected evidence.
To roll back adoption, disable the caller's connector invocation, keep prior
evidence private for review, and apply its retention policy. The SDK performs no
tenant actions, uploads or automatic raw-data migration.
