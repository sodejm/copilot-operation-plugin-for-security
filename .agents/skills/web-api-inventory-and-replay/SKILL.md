---
name: web-api-inventory-and-replay
description: List API endpoints from an OpenAPI file, Postman collection, HAR capture, or raw HTTP file; inspect redacted local inventory, draft replay plans, and run separately authorized bounded replays.
---

# Web API Inventory and Request Replay

Execute authorized web application and API inventory intake, endpoint modeling, session isolation, and bounded request replay under strict Rules of Engagement, destination allowlists, and operational budgets.

## Start with local evidence

Use this skill for “list the endpoints in this API specification,” “summarize
this browser capture,” or “help me plan an API test.” A user-provided local file
is enough to begin inventory or draft a plan; no live endpoint, credentials,
or execution approval is needed. Confirm permission to process the supplied
data, keep raw secrets out of model context, and use the local parser and
redaction checks. Inventory does not contact or authorize the listed servers.
Record missing scope as unresolved in draft plans.

## Observed service routing

These requirements apply to a service-evidence handoff or actual replay, not to
reading a supplied local schema or drafting a test plan.

1. Require observed HTTP protocol evidence and an exact scoped endpoint before routing. A port number or an HTTP guess does not establish a service.
2. Preserve only a sanitized request summary in prompts, handoffs, logs, and service evidence: the HTTP method; scheme, host, port, and path; query parameter names with every value replaced by `[REDACTED]`; response status; time; probe provenance; and, when needed, a digest of approved non-secret content. Never retain raw `Authorization`, `Proxy-Authorization`, `Cookie`, or `Set-Cookie` headers, API keys, tokens, query values, or request bodies.
3. Bind each replay request to an approved plan, one-use approval receipt, attempt budget, exact endpoint, and verifier. Follow redirects only when the approved destination list, fresh DNS and scope checks, TLS policy, cross-origin credential and body policy, and redirect-hop budget all permit the next hop. Never follow a newly discovered host outside the approval.
4. Report incomplete responses, authentication challenges, unexpected effects, and missing independent evidence as unresolved. Do not infer a verified finding from a status code alone.
5. The service-routing public journey remains the disposable loopback fixture in `docs/SERVICE_VALIDATION_PLAYBOOK.md`: `.venv/bin/python scripts/service_validation_loopback_example.py`. The separate API laboratory exercises object authorization and rate limiting as described below. These fixtures do not authorize external requests or establish production API assessment coverage.

## Core Capabilities

1. **Multi-Format Traffic & Schema Ingestion**:
   - **HAR (HTTP Archive 1.2)**: Normalizes captured browser or proxy traffic into deduplicated endpoint paths, methods, query parameters, header schemas, and response status codes.
   - **OpenAPI 3.x & Swagger 2.0**: Ingests API definitions, parameter schemas, request body definitions, server URLs, and security scheme declarations.
   - **Postman Collection (v2.0 & v2.1)**: Parses nested folders, requests, header arrays, query parameters, and collection/folder authentication configurations.
   - **Raw HTTP Transcripts**: Parses raw HTTP request blocks (`METHOD /path HTTP/1.1`) into modeled endpoints.

2. **Deterministic Credential Tokenization & Redaction**:
   - Matches authorization headers (`Bearer`, `Basic`), cookies, API keys, and sensitive parameter patterns (`password`, `secret`, `token`, `key`, `jwt`, `session`).
   - Irreversibly hashes raw secret values into truncated SHA-256 tokens (`[REDACTED:<hash>]`).
   - **Zero Plaintext Secrets**: Raw tokens and credentials never enter model context, logs, or stored inventory artifacts.

3. **Endpoint & Session Isolation Modeling**:
   - Models HTTP methods (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, etc.) and protocols (`http`, `graphql`, `websocket`).
   - Maps user roles (`UserRole`) and isolates active session contexts (`SessionContext`) to prevent session bleeding during authorization testing.
   - Flags unsupported protocol features (`UnsupportedFeature`) such as binary WebSocket streaming and Server-Sent Events (SSE).

4. **DestinationGuard & Scope Boundaries**:
   - Evaluates target URLs against explicit destination allowlists with support for exact hostnames and domain wildcards (`*.target.internal`).
   - Blocks unauthorized destinations immediately with a `403 Forbidden` synthetic response and records `destination_violations`.

5. **Bounded Operational Replay Engine**:
   - Constrained by `ReplayBudget`:
     - `max_requests`: Caps total dispatched requests.
     - `rate_limit_rps`: Enforces inter-request delay to prevent target denial of service.
     - `timeout_seconds`: Bounds network wait per request.
     - `max_redirect_hops`: Halts unbounded redirect loops.
     - `max_websocket_frames`: Bounds WebSocket frame exchanges.
   - Provides `OfflineSyntheticReplayer` for reproducible zero-egress CI/CD testing.
   - Live HTTP uses `build_replay_action_plan` and `execute_authorized_replay_session`; dispatch requires a matching approval, isolated worker, and `ScopeGuard`. Preview is side-effect free.

6. **Evidence-Based Control Assessment**:
   - Compares owner, other-user, and anonymous REST and GraphQL observations for BOLA/IDOR behavior.
   - Reports `pass`, `fail`, or `insufficient_evidence`; missing cases never become successful evidence.
   - Evaluates request-rate sequences for enforced `429` responses with retry guidance, unbounded success, or inconclusive evidence.

---

## Command Reference

### 1. Ingest Traffic and API Definitions into Sanitized Inventory

```bash
# Ingest OpenAPI / Swagger definition:
python3 -m cops web-api inventory --openapi docs/openapi.json --name "Payment API" -o inventory.json

# Ingest HAR traffic capture:
python3 -m cops web-api inventory --har captures/traffic.har --source-id ENG-04 -o inventory.json

# Ingest Postman Collection:
python3 -m cops web-api inventory --postman collections/api.postman_collection.json -o inventory.json

# Ingest Raw HTTP Request:
python3 -m cops web-api inventory --raw requests/test.http -o inventory.json
```

### 2. Inspect Inventory or Replay Report

```bash
# Inspect inventory summary, endpoints, roles, and redaction verification:
python3 -m cops web-api inspect inventory.json

# Inspect replay report results and destination compliance:
python3 -m cops web-api inspect replay_report.json
```

### 3. Execute Bounded Replay Session

```bash
# Execute offline synthetic replay:
python3 -m cops web-api replay \
  -i inventory.json \
  --allow-destination api.target.internal \
  --max-requests 50 \
  --rate-limit 10.0 \
  --mode offline \
  -o replay_report.json

# Live HTTP and bounded WS/WSS text replay are Python integration surfaces:
# 1. build_replay_action_plan(...)
# 2. verify approval for that exact plan
# 3. execute_authorized_replay_session(..., worker_identity=..., approval_control=..., scope_guard=...)
```

The package CLI rejects live mode until the shared CLI integrates the approval,
worker, and scope dependencies. Approved Python WebSocket replay supports only
bounded unfragmented UTF-8 text, ping/pong and checked close over WS/WSS. Bind all
messages and frame/byte/time limits to the plan; reject binary frames, fragments,
extensions, compression, subprotocols and WebSocket redirects. Local fixtures cover
REST/GraphQL authorization, rate limiting and WebSocket role sessions. They do not
establish OS/network isolation or production-provider qualification. Follow
`docs/BOUNDED_WEBSOCKET_REPLAY.md` for cancellation, partial evidence and recovery.
