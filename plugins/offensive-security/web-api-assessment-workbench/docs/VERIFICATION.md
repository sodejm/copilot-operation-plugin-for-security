# COPS Web API Assessment Workbench: end-to-end verification

This playbook qualifies the package's offline inventory and replay behavior and its disposable local authorization and request-rate assessment. It does not qualify a production provider.

## Scope and prerequisites

Run from a trusted checkout with the repository's declared Python environment. Use only synthetic fixtures or targets covered by explicit authorization. The supported inventory inputs are HAR 1.2, OpenAPI 3.x, Swagger 2.0, Postman 2.0/2.1, and raw HTTP transcripts. Import preserves the source artifact and emits a separate sanitized inventory.

The approved Python integration supports HTTP/HTTPS and a bounded WS/WSS text
subset. WebSocket replay requires an exact approved message sequence, isolated
session headers, frame/byte budgets and a checked close exchange. Binary frames,
fragmentation, compression, extensions, subprotocols and WebSocket redirects are
unsupported, as are binary streaming and Server-Sent Events. See
[bounded WebSocket replay](BOUNDED_WEBSOCKET_REPLAY.md).

The local acceptance laboratory starts disposable services on loopback and sends real HTTP requests. Its worker contract verifies readiness and coordinates execution, but it does not provide OS or network isolation. Record isolation as blocked. Production-provider validation is also incomplete.

## Baseline checks

Run `python3 -m pytest -q tests/test_web_api_import_safety.py` from the source
checkout. It verifies exact-byte and canonical-mapping hashes, digest mismatch
rejection, long inline inputs, origin separation, ambiguous Host rejection and
redaction across inventory, previews and replay reports. Serialized provenance
uses `sha256:<digest>`; retain the original source separately under its evidence
custody policy. Redaction does not replace classification of arbitrary source text.

Run each package entry point independently:

```bash
python3 -m cops info web-api-assessment-workbench
```

```bash
python3 -m cops demo web-api-assessment-workbench
```

```bash
python3 -m cops check web-api-assessment-workbench
```

The demo must report offline mode, zero network requests, a redacted inventory, and a bounded synthetic replay. The check result qualifies package-owned validation only; it is not production-provider evidence.

## End-to-end exercise

Run the focused local-service assessment with the repository environment:

```bash
make check-web-api-acceptance
```

Use `PYTHON=.venv/bin/python` when needed. This repository development gate invokes
the package's HTTP and WebSocket pytest acceptance modules and portable worker envelope,
plan, broker, integration and qualification tests, requires every named case, and rejects
skips, empty or incomplete collection, failed/malformed reports and timeout.
`make check` includes it; the portable `cops check` package gate remains offline
and does not execute these real-service cases. Hosts without Make can run
`python3 scripts/check_web_api_acceptance.py` from the repository root. The final
summary explicitly reports `scope: loopback-only` and `isolation_qualified: false`.
The worker qualification uses a patched sandbox. The separate Linux bubblewrap and
file-descriptor scrubber tests qualify generic sandbox boundaries; they do not prove an
integrated Web API production worker. Hosted CPython 3.15 checks and human security
review of the exact integrated revision remain separate closure gates.

The test issues signed authorizations through a persisted one-use approval store,
verifies consumption and rejects reuse or changed requests, sessions, destinations
and budget fields. Transport-focused tests also mutate caller input during approval
consumption, exercise trusted and rejected TLS handshakes, preserve completed HTTP
error responses and verify redirect credential and body boundaries. This local
authority does not prove independent administration in production.

The test starts vulnerable and corrected loopback services and sends requests through the `ActionPlan`, approval verification, worker-readiness, and scope controls. It covers owner, other-user, and anonymous cases for REST BOLA/IDOR and GraphQL object access. It also covers an unbounded-success rate failure, a corrected `429` with retry guidance, and a sequence that is too short to support a conclusion.

For an imported inventory, preview any proposed live operation before approval:

```bash
python3 -m cops web-api replay -i inventory.json --allow-destination api.target.internal --max-requests 25 --rate-limit 5 --mode live --dry-run --json
```

The preview must name exact target and allowed destinations, request and redirect budgets, expected evidence, unsupported features, and effects. It must not dispatch requests, request approval, start a worker, create a session, mutate state, or write replay output.

## Acceptance criteria

- HAR 1.2, OpenAPI 3.x, Swagger 2.0, Postman 2.0/2.1, and raw HTTP fixtures produce normalized inventories while their source files remain unchanged.
- Credential-bearing headers, cookies, query values, and bodies are redacted before inventory or replay evidence is stored or displayed.
- Preview reports the exact destinations, budget, evidence plan, unsupported features, and zero effects without network, approval, worker, session, or file activity.
- The vulnerable service yields failed object-authorization findings when another user or an anonymous caller reaches a protected REST or GraphQL object. The corrected service permits the owner and denies both non-owner roles.
- A bounded all-success request sequence yields a failed rate-limit finding; a `429` with retry guidance yields a passed finding; missing attempts or transport/server errors yield `insufficient_evidence`.
- Loopback integration exercises check rejection of action-plan drift, unapproved execution, unready workers, out-of-scope destinations, excess redirects, and exhausted request budgets before further dispatch.
- Loopback integration exercises check owned snapshots, TLS certificate and hostname verification, HTTPS downgrade rejection, and refusal of cross-origin redirects retaining a body or credential-bearing header. They do not qualify production isolation.
- Unsupported protocols and missing evidence remain explicit limitations. They never become successful evidence.
- Response-body serialization retains only opaque digests and an optional Boolean
  GraphQL object-access observation. Explicit denial, object disclosure and unknown
  outcomes survive repeated report round trips without saving payloads or error
  messages. Old digest-only evidence without this observation stays inconclusive;
  recollect the exact missing authorized case rather than inferring an outcome.

## Failure and recovery

If the environment blocks loopback binding, record the local-service exercise as blocked with the command and error. Do not replace real-service evidence with a synthetic success. Re-run unchanged in an environment that permits disposable loopback listeners.

If approval, worker readiness, scope, redirect, or budget validation fails, preserve the sanitized failure report, correct the plan or environment, obtain a new approval for the exact revised `ActionPlan`, and restart with a fresh bounded session. Supply the same isolated role sessions to plan construction and execution; tool
version 2 binds their effective credentials, the entire budget and the destination
allowlist. Never reuse a session across roles. Treat HTTP error statuses as observed
responses, and transport failures as uncertain effects requiring review before
a new attempt. If any required owner, other-user, anonymous, REST, GraphQL, or rate observation is absent, record `insufficient_evidence` and collect only the missing authorized case.

## Host exercise

Install or load the package through the intended host marketplace, then run the same `info`, `demo`, and `check` entry points and record package discovery plus their exit status. Confirm that the host exposes inventory, inspect, and replay preview without expanding the package's destination or budget controls.

No production provider adapter or provider-target result has been validated. A
provider exercise requires separate authorization, an exact destination allowlist,
an approved `ActionPlan`, repository worker and scope controls, and evidence from
the actual provider service. Bounded WS/WSS text exchanges are locally exercised;
that does not establish arbitrary WebSocket application or provider support.

## Record and promote

Record the repository revision, interpreter version, source-fixture digests, commands, exit codes, sanitized reports, vulnerable/corrected profile, destinations, budgets, and any blocked or insufficient cases. Keep credentials and private endpoint details out of retained evidence.

Promotion requires the baseline commands and local-service acceptance to pass in the intended host, plus separate resolution of the isolation blocker and production-provider validation. Until then, describe the package as locally validated for the documented inventory, preview, offline replay, and loopback assessment behavior only.

## Issue 100 worker integration

Use the [Issue #100 worker qualification contract](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/100)
to record exact-revision acceptance, Linux isolation, installed/exported package,
hosted CPython 3.15 and human security review evidence. An unavailable gate remains
unverified; portable package and loopback results do not qualify production isolation.
