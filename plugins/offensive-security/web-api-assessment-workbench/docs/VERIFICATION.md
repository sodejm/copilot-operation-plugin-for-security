# COPS Web API Assessment Workbench: end-to-end verification

This playbook qualifies the package's offline inventory and replay behavior and its disposable local authorization and request-rate assessment. It does not qualify a production provider.

## Scope and prerequisites

Run from a trusted checkout with the repository's declared Python environment. Use only synthetic fixtures or targets covered by explicit authorization. The supported inventory inputs are HAR 1.2, OpenAPI 3.x, Swagger 2.0, Postman 2.0/2.1, and raw HTTP transcripts. Import preserves the source artifact and emits a separate sanitized inventory.

HTTP and HTTPS are the only live replay protocols available through the approved Python integration. WebSocket entries are inventory only. WebSocket replay, binary streaming, and Server-Sent Events are unsupported.

The local acceptance laboratory starts disposable services on loopback and sends real HTTP requests. Its worker contract verifies readiness and coordinates execution, but it does not provide OS or network isolation. Record isolation as blocked. Production-provider validation is also incomplete.

## Baseline checks

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
python3 -m pytest -q plugins/offensive-security/web-api-assessment-workbench/tests/test_authorized_assessment.py
```

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
- Approved live HTTP replay rejects action-plan drift, unapproved execution, unready workers, out-of-scope destinations, excess redirects, and exhausted request budgets before further dispatch.
- Unsupported protocols and missing evidence remain explicit limitations. They never become successful evidence.

## Failure and recovery

If the environment blocks loopback binding, record the local-service exercise as blocked with the command and error. Do not replace real-service evidence with a synthetic success. Re-run unchanged in an environment that permits disposable loopback listeners.

If approval, worker readiness, scope, redirect, or budget validation fails, preserve the sanitized failure report, correct the plan or environment, obtain a new approval for the exact revised `ActionPlan`, and restart with a fresh bounded session. Never reuse a session across roles. If any required owner, other-user, anonymous, REST, GraphQL, or rate observation is absent, record `insufficient_evidence` and collect only the missing authorized case.

## Host exercise

Install or load the package through the intended host marketplace, then run the same `info`, `demo`, and `check` entry points and record package discovery plus their exit status. Confirm that the host exposes inventory, inspect, and replay preview without expanding the package's destination or budget controls.

No production provider adapter or provider-target result has been validated. A provider exercise requires separate authorization, an exact destination allowlist, an approved `ActionPlan`, repository worker and scope controls, and evidence from the actual provider service. WebSocket behavior can be inventoried but cannot be replayed by this package.

## Record and promote

Record the repository revision, interpreter version, source-fixture digests, commands, exit codes, sanitized reports, vulnerable/corrected profile, destinations, budgets, and any blocked or insufficient cases. Keep credentials and private endpoint details out of retained evidence.

Promotion requires the baseline commands and local-service acceptance to pass in the intended host, plus separate resolution of the isolation blocker and production-provider validation. Until then, describe the package as locally validated for the documented inventory, preview, offline replay, and loopback assessment behavior only.
