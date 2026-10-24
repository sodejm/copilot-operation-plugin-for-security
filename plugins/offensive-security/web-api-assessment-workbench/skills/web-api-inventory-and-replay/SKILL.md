---
name: web-api-inventory-and-replay
description: List API endpoints from an OpenAPI file, Postman collection, HAR capture, or raw HTTP file; inspect redacted local inventory, draft replay plans, and run separately authorized bounded replays.
---

# Web API Inventory and Request Replay

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

## Inventory and replay

1. For local ingestion, confirm permission to process the supplied file and protect sensitive content. Require explicit target scope authorization and a destination allowlist before live replay; a local inventory is not execution approval.
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
