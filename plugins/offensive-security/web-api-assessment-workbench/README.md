# COPS Web API Assessment Workbench

The **Web API Assessment Workbench** enables security engineers, penetration testers, and application security reviewers to build structured API inventories, model endpoints and bounded session contexts, and prepare controlled request replays under strict destination allowlists.

Modern web applications and APIs span RESTful microservices, GraphQL gateways, and real-time WebSocket channels. Probing these endpoints during authorized security assessments requires strict discipline: captured traffic can contain plaintext credentials, unconstrained clients can trigger denial of service or out-of-scope egress, and session bleeding between roles can distort authorization findings.

The Web API Assessment Workbench provides **structured intake, deterministic token redaction, and bounded replay gates**:
- **Multi-Format Traffic & Schema Ingestion**: Import HTTP captures (HAR 1.2), API schemas (OpenAPI 3.x, Swagger 2.0), Postman collections (v2.0, v2.1), and raw HTTP request transcripts.
- **Deterministic Credential Redaction**: Tokenizes and redacts sensitive credentials (Authorization headers, session cookies, API tokens, passwords) using irreversible SHA-256 hashes (`[REDACTED:<hash>]`) before they enter stored inventory and replay evidence.
- **Endpoint & Session Modeling**: Organizes endpoints by method, protocol (HTTP, GraphQL, WebSocket), path, and authorization requirements, isolating distinct role sessions.
- **DestinationGuard & Budget Boundaries**: Bounded replay strictly enforces allowed target hosts/IPs, maximum request counts, rate limits (RPS), timeout limits, and redirect hop ceilings.
- **Evidence-Based Authorization Assessment**: Classifies owner, other-user, and anonymous REST and GraphQL observations as `pass`, `fail`, or `insufficient_evidence` without treating missing cases as success.
- **Rate-Limit Assessment**: Distinguishes an enforced `429` with retry guidance from an unbounded success sequence or inconclusive transport/server evidence.
- **Protocol Transparency**: Transparently models unsupported protocol features (such as binary streaming or Server-Sent Events) to prevent silent execution anomalies.

---

## When to Use & Security Engineer Playbook

For the operating workflow, see the [Web API Assessment Playbook](docs/PLAYBOOK.md). For repeatable qualification and evidence requirements, see [Web API Assessment Verification](docs/VERIFICATION.md).

Use this workbench when:
- **Auditing Web Application & API Surfaces**: Consolidating diverse API definitions and observed HTTP traffic into a normalized, sanitized asset inventory.
- **Validating Authorization & Session Boundaries**: Testing endpoint accessibility across isolated user roles without session bleeding.
- **Executing Controlled API Replays**: Replaying request sequences against authorized targets with strict rate limits, redirect bounds, and egress guards.
- **Testing REST and GraphQL Controls**: Verifying object authorization and request-rate controls across owner, other-user, and anonymous sessions.

---

## Usage

Run the three package entry points independently from the repository root:

```bash
python3 -m cops info web-api-assessment-workbench
```

```bash
python3 -m cops demo web-api-assessment-workbench
```

```bash
python3 -m cops check web-api-assessment-workbench
```

The demo is offline and synthetic. The check runs the package-owned offline validation;
it does not execute the local-service acceptance suite or qualify a production
target or provider. In a prepared source checkout, run `make check-web-api-acceptance`
for all required disposable-loopback authorization cases. Repository `make check`
requires that separate gate; neither gate establishes OS/network isolation.

### Quick Test Drive (Offline Demo)

Execute the offline demonstration showing OpenAPI schema ingestion, automatic token redaction, and synthetic bounded request replay:

```bash
python3 -m cops demo web-api-assessment-workbench

# Or run the demo directly:
python3 plugins/offensive-security/web-api-assessment-workbench/scripts/demo.py
```

### Expected Output
The demo verifies zero network egress (`network_requests: 0`), imports endpoints, applies deterministic redaction, and executes an offline replay session bounded by budget and destination allowlists:
```json
{
  "inventory": {
    "credentials_redacted": true,
    "endpoints_count": 4,
    "name": "OpenAPI Spec: Secure Vault API",
    "target_hosts": [
      "api.vault.internal"
    ]
  },
  "mode": "offline",
  "network_requests": 0,
  "replay_summary": {
    "destination_violations": 0,
    "session_id": "rep-sess-f061a1e7d1e1",
    "total_dispatched": 4,
    "total_failed": 0,
    "total_successful": 4
  },
  "status": "passed"
}
```

---

### Inventory and replay commands

The workbench is exposed via the unified `cops web-api` command:

```bash
# 1. Import API traffic / definitions into a sanitized inventory
python3 -m cops web-api inventory --openapi spec.json --output inventory.json
python3 -m cops web-api inventory --har traffic.har --source-id ENG-01 -o inventory.json
python3 -m cops web-api inventory --postman collection.json -o inventory.json
python3 -m cops web-api inventory --openapi public.json --openapi admin.json -o combined.json

# 2. Inspect an existing inventory or replay session report
python3 -m cops web-api inspect inventory.json

# 3. Preview a bounded replay without dispatching requests or writing output
python3 -m cops web-api replay \
  -i inventory.json \
  --allow-destination api.target.internal \
  --max-requests 25 \
  --rate-limit 5.0 \
  --mode live \
  --dry-run \
  --json

# 4. Execute an offline synthetic replay with destination guard
python3 -m cops web-api replay \
  -i inventory.json \
  --allow-destination api.target.internal \
  --max-requests 25 \
  --rate-limit 5.0 \
  --mode offline \
  -o replay_report.json
```

The package CLI supports offline replay only and rejects live dispatch. Source-level
integration exercises use disposable loopback services; qualification of the
approved isolated worker and production providers remains pending. Live execution
requires exact approval and the isolated worker and egress controls described in
the [verification guide](docs/VERIFICATION.md#issue-100-worker-integration).

The loopback exercises include a [bounded WS/WSS text subset](docs/BOUNDED_WEBSOCKET_REPLAY.md):
one fresh connection, exact approved UTF-8 messages, one reply per message and a
checked close. Counts include control and close frames in both directions;
`max_websocket_message_bytes` and `max_websocket_bytes` bound payload and aggregate
encoded frame bytes. Binary frames, fragments, compression, extensions,
subprotocols, WebSocket redirects and SSE remain unsupported. The CLI does not
enable live dispatch. Use `--max-frames`, `--max-message-bytes` and
`--max-websocket-bytes` to expose the intended budgets in a CLI preview.

`max_requests` bounds the submitted batch. Preview, plan construction, offline
replay, and approved live replay reject an oversized batch before dispatch or
report construction rather than truncating it. Accepted offline batches preserve
request ordering and report every request, including destination rejections and
synthetic runtime outcomes.

Destination allowlist items accept exact ASCII DNS names and canonical dotted-decimal IPv4 addresses, optionally followed by a decimal port from 1 through 65535, and bracketed numeric IPv6 addresses with the same optional port. `*.example.test` is the only wildcard form; it accepts no port and matches the apex and subdomains. Every entry point takes a shallow container snapshot and syntax-checks every item without name resolution before retaining the allowlist. A malformed item rejects the complete list even when unused, without copying its value into errors, reports, or formatted exception chains.

## Design and data flow

Importers normalize HAR 1.2, OpenAPI 3.x, Swagger 2.0, Postman 2.0/2.1, and raw HTTP into the same redacted inventory without rewriting the source artifact. Replay preparation converts inventory endpoints into bounded requests, checks exact destinations and limits, and produces a side-effect-free preview. Offline replay uses synthetic responses. Live HTTP replay is available only through the approved Python integration described above; no provider adapter is claimed.

Every import format has an 8 MiB input ceiling enforced by a bounded
maximum-plus-one binary read before parsing; accepted artifacts retain their
exact raw-byte SHA-256 digest. Import flags are repeatable, including multiple
inputs of the same type. A merged inventory retains every source in
`provenance_sources` and derives a deterministic identity from sorted opaque
source IDs, source types, and content digests. Provenance serialization rejects
local paths, credential-bearing references, invalid digests, and mismatched
`sha256:<digest>` references. Saved inventories and replay reports use the same
8 MiB bounded binary reader. The inspection command validates and reserializes
recognized public models; inventory names and imported-source labels reject
local or credential-bearing references at both public boundaries.
Endpoint and session authentication metadata is validated at both boundaries.
It must be explicitly redacted, with either an empty declaration-only credential
identity or a canonical lowercase SHA-256 digest. Plaintext and malformed values
fail with a content-free error.

OpenAPI and Swagger imports apply operation security overrides before creating replay credentials. An empty security array is public, unused declarations do not create sessions, and anonymous or alternative requirements are not combined into stronger authentication. Basic and Bearer use `Authorization`; header API-key names collide case-insensitively, while query API-key names are case-sensitive. OpenAPI operation/path/root server precedence and Swagger `basePath` are preserved in preview URLs. The importer deterministically selects the first declared server alternative and reports the remaining alternatives as unsupported. Relative or non-HTTPS servers, unresolved variables, empty-host or malformed-port authorities, unknown or unrepresentable security requirements, and operation path keys containing `?` or `#` fail closed without importing their content into an error.

Every newly imported authenticated endpoint carries an explicit `session_id`.
Serialization and merge retain the endpoint-to-session association, and merge
namespaces endpoint and session IDs by source occurrence. Duplicate inputs and
different inputs using the same scheme therefore keep distinct credential
contexts through preview, action-plan construction, and offline replay. This
applies to supported Bearer, Basic, and API-key authentication from HAR,
OpenAPI/Swagger, Postman, and raw HTTP. Missing, conflicting, or ambiguous
bindings fail closed.

HAR Bearer and Basic metadata use the header name `Authorization`, and previews
render `Authorization: Bearer <placeholder>` or
`Authorization: Basic <placeholder>`. The CLI does not load credentials from
the environment. An approved integration replaces a Bearer placeholder with
the token only (no scheme prefix), a Basic placeholder with the RFC 7617
base64-encoded `user:password` payload only (no scheme prefix), and an API-key
placeholder with the exact header, query, or cookie value only. Suggested
environment names are `COPS_WEB_API_BEARER_TOKEN`,
`COPS_WEB_API_BASIC_CREDENTIALS_B64`, and `COPS_WEB_API_API_KEY_VALUE`.

| Artifact | Purpose | Producer | Consumer | Validation |
| :--- | :--- | :--- | :--- | :--- |
| Sanitized API inventory | Normalized endpoints, protocols, parameters, target hosts, and source references | HAR 1.2, OpenAPI 3.x/Swagger 2.0, Postman 2.0/2.1, or raw HTTP importer | Inspect, preview, and replay preparation | Schema construction, credential redaction, source-format tests, and inventory inspection |
| Replay preview | Exact request URLs, allowed and target destinations, budget, sanitized evidence, zero effects, and unresolved live observations | `cops web-api replay --dry-run` or `--explain` | Operator and approval planning | Destination and budget validation; tests assert no dispatch, worker, authorization, session, file, or state effects |
| Replay report | Sanitized response observations and bounded execution totals | Offline synthetic replayer or loopback test integration | Authorization and rate-limit assessors | Request budget, destination guard, redirect bounds, response redaction, and report-schema tests |
| Authorization/rate assessment | `pass`, `fail`, or `insufficient_evidence` verdict with case evidence | Object-authorization and rate-limit assessors | Reviewer and evidence record | Owner, other-user, and anonymous REST/GraphQL cases plus bounded `429`, all-success, and incomplete sequences |

## Local Acceptance Fixture

`WebApiAssessmentLaboratory` starts disposable loopback HTTP services in either `vulnerable` or `corrected` mode. Focused tests send real requests through the ActionPlan, approval, worker-readiness, and scope boundaries and verify REST BOLA/IDOR, GraphQL object authorization, and rate-limit failures, fixes, and insufficient evidence. The worker boundary does not provide OS or network isolation, so isolation is still blocked. These local results do not establish behavior for a production provider.

---

## Package Validation

Validate the package integrity, unit tests, and reproducibility gates:

```bash
python3 -m cops check web-api-assessment-workbench
```

Follow [Web API Assessment Verification](docs/VERIFICATION.md) to record the baseline, local-service evidence, failure recovery, and remaining qualification gaps.

Serialized replay evidence stores only digest redaction markers for request bodies, response excerpts, GraphQL queries, and WebSocket payloads. Opaque payloads and custom JSON fields may contain credentials, so reports do not retain their content. This reporting policy does not change in-memory assessment inputs or approved wire requests.

HAR, Postman, and absolute raw HTTP request imports preserve their source URL scheme in inventory round trips and replay previews, including HTTP versus HTTPS and WS versus WSS. Legacy inventories and relative raw requests without a recorded scheme retain the existing HTTPS (or modeled WebSocket WSS) default. Recorded schemes outside these four transports fail preview construction. Approved WebSocket execution requires an explicit WS/WSS destination; it never silently rewrites an HTTP URL into a WebSocket connection.

OpenAPI imports require exactly one supported version declaration: `swagger: "2.0"` or an `openapi` string in `3.x.y` form. Missing, malformed, conflicting, and other major versions fail before inventory generation.

Path-level OpenAPI/Swagger parameters are inherited by each operation. An operation overrides a shared parameter with the same name and location; an empty operation parameter list retains inherited parameters. Malformed declarations, duplicate identities within one level, and unresolved parameter references fail closed.

## Worker integration qualification

The [Issue #100 worker qualification guidance](docs/VERIFICATION.md#issue-100-worker-integration)
records the required isolated-worker, approval, egress, evidence and cleanup gates.
Those requirements must be verified on the integrated revision before claiming
worker or production qualification; the offline CLI remains non-dispatching.
