---
name: web-api-inventory-and-replay
description: Ingest HTTP traffic and API descriptions, model endpoints and isolated sessions with redacted credentials, and execute bounded request replays under destination allowlists.
---

# Web API Inventory and Request Replay

1. Confirm explicit target scope authorization and destination allowlist before executing any API ingestion or replay.
2. Ingest API traffic captures or schemas using repository-owned commands:
   - HAR 1.2: `python3 -m cops web-api inventory --har <traffic.har> -o inventory.json`
   - OpenAPI 3.x / Swagger: `python3 -m cops web-api inventory --openapi <spec.json> -o inventory.json`
   - Postman Collection: `python3 -m cops web-api inventory --postman <collection.json> -o inventory.json`
   - Raw HTTP: `python3 -m cops web-api inventory --raw <request.http> -o inventory.json`
3. Inspect the parsed inventory with `python3 -m cops web-api inspect inventory.json` and verify that all credential tokens, cookies, and secrets are deterministically redacted (`[REDACTED:<hash>]`).
4. Enforce strict destination boundaries using `DestinationGuard`. Reject any target URL not explicitly listed in the authorized allowlist.
5. Preview or synthetically replay request sequences bounded by operational budgets (max requests, rate limiting RPS, timeout, max redirect hops):
   `python3 -m cops web-api replay -i inventory.json --allow-destination <target.host> --max-requests 50 --rate-limit 10.0 -o replay_report.json`
6. For live HTTP, build an `ActionPlan`, verify approval for that exact snapshot, then call `execute_authorized_replay_session` with the repository worker and `ScopeGuard`. Preview must remain side-effect free.
7. Compare owner, other-user, and anonymous REST and GraphQL observations with `assess_object_authorization`; evaluate bounded rate evidence with `assess_rate_limit`. Treat missing or indeterminate evidence as `insufficient_evidence`.
8. Review replay session reports for status distribution, latency benchmarks, and destination compliance.

The package CLI supports offline replay and rejects live mode until the shared CLI integrates approval, worker, and scope dependencies. Live WebSocket execution is unsupported. Loopback vulnerable/corrected fixtures validate local BOLA/IDOR, GraphQL, and rate-limit behavior; production-provider validation remains incomplete.
