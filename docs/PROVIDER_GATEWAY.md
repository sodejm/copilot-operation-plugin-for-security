# Operator provider gateway boundary

The provider gateway is the only approved boundary for the versioned live assessment plan. The current repository implementation exercises that boundary with synthetic provider envelopes, a signed one-use gateway emulator, and a broker-backed transport adapter tested without a network. It does not call a provider, use provider credentials, or establish production readiness. The existing offline assessment command and schema remain unchanged.

## Opt-in live contract and synthetic validation

The live plan is a separate, versioned contract and must be explicitly enabled. Its paid-execution opt-in records operator intent; it does not by itself authorize production dispatch. The plan pins the gateway HTTPS origin and path independently of the provider request target. Synthetic validation accepts only approved request bodies and bounded responses for the four supported provider envelope shapes.

The live runner must fail closed when the plan, request, signed grant, shared budget, configured gateway origin and path, gateway endpoint, or worker identity is missing or inconsistent. Tests and operator demonstrations must use the gateway emulator or a broker test double with no external route. No real provider request, credential lookup, or paid call is permitted in this phase.

The emulator accepts a deliberately narrow, text-only request shape. OpenAI and Azure use the Responses endpoint with `model`, string `input`, the approved `max_output_tokens`, `store: false`, and `stream: false`. Bedrock Converse uses one user text message and `inferenceConfig.maxTokens`; Vertex `generateContent` uses one user text part and `generationConfig.maxOutputTokens`. The model and, for Vertex, project and region must also match the exact endpoint path. Extra request keys, including provider tool declarations or remote attachment references, are denied even when their body digest is approved. Provider tool output remains an inert proposal for separate authorization.

## Signed authorization and exact plan binding

Each dispatch requires a short-lived, signed, one-use grant issued outside the worker. Before reserving budget, the runner performs a non-consuming preflight using values independently derived from the approved live plan and request. It compares all of these bindings exactly:

- dispatch and authorization identifiers;
- action-plan identifier and canonical plan digest;
- presented worker SPIFFE identity;
- provider, account or project, region, and model;
- configured gateway endpoint identifier, HTTPS origin, and path;
- canonical absolute HTTPS provider request target;
- canonical request-body SHA-256 digest and byte length; and
- grant issuance and expiry bounds.

Expected values must come from the approved plan and request, never from the grant being checked. The gateway independently verifies the signature, trusted endpoint policy, expiry, and replay state. It durably consumes the authorization before invoking the emulator handler. A consumed, dispatched, settled, released, or uncertain attempt cannot trigger another dispatch. Timeouts and ambiguous outcomes are never replayed automatically.

The operator keeps the signing key outside the worker and equips the gateway with an owner-protected public-key trust store and durable replay store. The replay store must enforce uniqueness for both dispatch and authorization IDs; legacy stores without the authorization ID column fail closed until migrated with their consumption history intact. An unavailable replay store denies dispatch.

The provider request target is authorization data for the gateway. It is distinct from the gateway transport origin and must never become a direct worker egress destination.

## Gateway origin, worker identity, and credentials

The configured gateway origin and path are the worker's only network destination for this flow. The v2 broker carries one bounded POST body to that endpoint and rejects redirects, automatic retries, and direct provider destinations. Production transport must authenticate the worker with mTLS and SPIFFE and enforce these restrictions outside the same-authority test process. The worker must not retry a dispatch automatically.

The gateway owns provider credential resolution and limits credentials to the approved provider scope. Plans, grants, request fixtures, reports, and logs must not contain provider secrets. By default the emulator has no credential resolver or provider transport. An operator may install the local `GatewayScopedProviderHandler` with an exact endpoint-to-credential-reference binding, resolver, and synthetic transport. It resolves the credential after scope verification and one-use grant consumption. Its supplied transport still needs its own TLS, IAM, and destination enforcement before production use. Keep retained bodies and resolver failures out of logs and assessment evidence.

## Budget, cancellation, and cleanup

Live assessment uses the shared `AssessmentBudgetLedger`; it must not create a parallel budget model. The safe order is:

1. Verify the signed grant and exact plan/request bindings without consuming the grant or reserving budget.
2. Reserve the approved worst-case amount in the shared ledger and require a newly `reserved` attempt.
3. Mark the attempt dispatched immediately before the gateway send.
4. Settle only from trustworthy outcome evidence, or mark the attempt uncertain.

A reservation may be released only when the gateway proves that no send occurred. After dispatch, a timeout, disconnect, cancellation, cleanup failure, process interruption, malformed response, or other unknown outcome leaves the attempt `uncertain` and retains the conservative reservation. Local cancellation and cleanup do not prove that a remote request stopped or that remote data was deleted.

The emulator runner bounds its wait for a dispatch by the smaller of the approved request time estimate and the remaining engagement wall-clock budget. A timed-out handler can still finish in the background; the runner does not treat the timeout as remote cancellation and cannot reuse that authorization. A production gateway transport must enforce its own network deadline and account for an in-flight request independently.

The gateway accepts at most 1 MiB of response bytes. The live plan must reserve no more than that limit for each response, and the runner rejects an actual response larger than its approved reservation before parsing it. A response-size overrun after dispatch leaves the attempt uncertain and charged.

## Evidence, tool proposals, and billing

Public results and retained evidence contain redacted metadata and digests only. They must not expose provider response text, raw response bodies, or tool-argument JSON. Provider tool calls are inert proposals: the runner rejects names outside the plan allowlist and never executes a proposal without a separate authorization path.

Provider, emulator, or gateway usage and cost fields are estimates or unverified observations. Missing or partial usage never lowers the reservation automatically. A cost may be labeled reconciled only after a separate trusted process verifies an independent provider billing export, invoice, or equivalent billing record. A gateway-reported amount is not independent billing evidence.

## Residency, retention, and deletion

The approved provider scope pins the account or project and region. Before production use, operators must verify the complete gateway-to-provider data path, applicable residency controls, provider and gateway retention, deletion behavior, and evidence redaction. Requests must explicitly disable provider retention where the provider supports that setting.

Current fixtures and responses are synthetic. They demonstrate contract handling only and do not establish provider residency, non-retention, deletion, or privacy behavior.

## Production evidence gate

Production dispatch remains disabled until evidence for the exact deployed revision demonstrates all of the following:

- gateway-only egress from the isolated worker, with direct provider egress denied;
- deployed mTLS and SPIFFE worker authentication and exact gateway-origin pinning;
- protected signing-key custody, gateway-owned scoped credential custody, and rotation procedures;
- durable one-use authorization enforcement under concurrency and restart;
- shared-budget reservation, uncertain accounting, cancellation, and cleanup behavior under failure;
- verified provider scope, residency, retention, deletion, redaction, and independent billing reconciliation; and
- engagement approval for the exact plan, request digests, tool allowlist, budget, worker, gateway, and provider scope.

The emulator can prove protocol validation, replay handling, conservative accounting, and redacted evidence. It cannot prove that a production worker, gateway, credential resolver, provider, or billing system satisfies these controls. No real provider calls are part of this increment.

The existing worker supervisor documents a deployed `GET`/`HEAD` operation path. The v2 broker-backed POST adapter is validated with synthetic transports, but it has not been exercised on a production worker or gateway. Review and verify that integration at its exact deployed revision before enabling a real canary. Verify the intended worker's SSH host key, isolation, authority service, egress policy, and gateway identity independently.
