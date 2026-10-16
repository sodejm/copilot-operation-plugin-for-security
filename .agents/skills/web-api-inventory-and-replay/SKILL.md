---
name: web-api-inventory-and-replay
description: Route observed HTTP service entries to bounded, approved API inventory and request replay. Current executable validation is limited to the disposable loopback service laboratory.
---

# Web API inventory and replay

1. Require observed HTTP protocol evidence and an exact scoped endpoint before routing. A port number or an HTTP guess does not establish a service.
2. Preserve only a sanitized request summary in prompts, handoffs, logs, and evidence: the HTTP method; scheme, host, port, and path; query parameter names with every value replaced by `[REDACTED]`; response status; time; probe provenance; and, when needed, a digest of approved non-secret content. Never retain raw `Authorization`, `Proxy-Authorization`, `Cookie`, or `Set-Cookie` headers, API keys, tokens, query values, or request bodies.
3. Bind each replay request to an approved plan, one-use approval receipt, attempt budget, exact endpoint, and verifier. Do not automatically follow redirects or newly discovered hosts.
4. Report incomplete responses, authentication challenges, unexpected effects, and missing independent evidence as unresolved. Do not infer a verified finding from a status code alone.
5. Current executable validation is the disposable loopback fixture in `docs/SERVICE_VALIDATION_PLAYBOOK.md`. Run its public journey with `.venv/bin/python scripts/service_validation_loopback_example.py`. This does not authorize external requests or establish native API assessment coverage.
