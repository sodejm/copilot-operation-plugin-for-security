---
name: web-api-inventory-and-replay
description: Ingest HTTP traffic (HAR 1.2), OpenAPI 3.x/Swagger 2.0, Postman collections, and raw HTTP descriptions; model endpoints and isolated sessions with deterministic credential redaction; and execute bounded request replays under strict destination allowlists.
---

# Web API Inventory and Request Replay

Execute authorized web application and API inventory intake, endpoint modeling, session isolation, and bounded request replay under strict Rules of Engagement, destination allowlists, and operational budgets.

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

# Live HTTP is a Python integration surface:
# 1. build_replay_action_plan(...)
# 2. verify approval for that exact plan
# 3. execute_authorized_replay_session(..., worker=..., scope_guard=...)
```

The package CLI rejects live mode until the shared CLI integrates the approval, worker, and scope dependencies. Live WebSocket execution is unsupported. The local vulnerable/corrected fixture validates REST and GraphQL object authorization and rate limiting; production-provider validation remains incomplete.
