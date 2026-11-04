# Operator provider gateway boundary

The provider gateway is the only approved boundary for the versioned live assessment plan. Version 2 remains an emulator-only historical contract. Version 3 requires the `GatewayProductionDispatcher` and a registered, versioned, gateway-owned provider adapter. The repository also includes synthetic provider envelopes and a broker-backed worker transport. Registration and controlled tests do not establish production readiness or authorize a live call. The existing offline assessment command and schema remain unchanged.

## Opt-in live contract and synthetic validation

The live plan is a separate, versioned contract and must be explicitly enabled. Its paid-execution opt-in records operator intent; it does not by itself authorize production dispatch. The plan pins the gateway HTTPS origin and path independently of the provider request target. Synthetic validation accepts only approved request bodies and bounded responses for the four supported provider envelope shapes. A v2 plan cannot use the production dispatcher, and a v3 plan cannot use the emulator dispatcher.

The live runner must fail closed when the plan, request, signed grant, shared budget, configured gateway origin and path, gateway endpoint, or worker identity is missing or inconsistent. Disposable tests use controlled endpoints and credentials, not real provider accounts. A paid call requires separate engagement authorization and the production evidence below.

Both versions accept a deliberately narrow, text-only request shape. OpenAI and Azure use the Responses endpoint with `model`, string `input`, the approved `max_output_tokens`, `store: false`, and `stream: false`. Bedrock Converse uses one user text message and `inferenceConfig.maxTokens`; Vertex `generateContent` uses one user text part and `generationConfig.maxOutputTokens`. The model and, for Vertex, project and region must also match the exact endpoint path. Extra request keys, including provider tool declarations or remote attachment references, are denied even when their body digest is approved. The v2 emulator can classify supported synthetic tool output only as an inert proposal. Production adapters reject tool output and every other non-text or unknown output before it crosses the gateway boundary.

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

Version 3 additionally binds `execution_class: production`, opaque auth-profile and credential-reference identifiers, the exact adapter transport version, endpoint-policy and worker-evidence digests, and positive request ceilings for output tokens, response bytes, and elapsed time. These values must match the plan, case, grant, and runtime configuration exactly.

Expected values must come from the approved plan and request, never from the grant being checked. The gateway independently verifies the signature, trusted endpoint policy, expiry, and replay state. Production dispatch also uses the gateway's current clock; callers cannot inject an earlier verification time to revive an expired grant. Test-only time injection remains limited to the v2 emulator boundary. The gateway durably consumes the authorization before invoking the configured handler. A consumed, dispatched, settled, released, or uncertain attempt cannot trigger another dispatch. Timeouts and ambiguous outcomes are never replayed automatically.

The operator keeps the signing key outside the worker and equips the gateway with an owner-protected public-key trust store and durable replay store. The replay store must enforce uniqueness for both dispatch and authorization IDs; legacy stores without the authorization ID column fail closed until migrated with their consumption history intact. An unavailable replay store denies dispatch.

The provider request target is authorization data for the gateway. It is distinct from the gateway transport origin and must never become a direct worker egress destination.

## Gateway origin, worker identity, and credentials

The configured gateway origin and path are the worker's only network destination for this flow. The v2 broker carries one bounded POST body to that endpoint and rejects redirects, automatic retries, and direct provider destinations. For v3, the production dispatcher executes inside the gateway boundary; only its registered adapter may open the exact provider HTTPS connection, and the worker receives only the normalized, redacted result. Production transport must authenticate the worker with mTLS and SPIFFE and enforce these restrictions outside the same-authority test process. The worker must not retry a dispatch automatically.

The gateway owns provider credential resolution and limits credentials to the approved provider scope. Operators provision credential profiles outside the worker, map an opaque credential reference to the exact approved provider, account or project, region, model, and HTTPS endpoint, and protect the profile and secret store under gateway control. References identify credentials; they are not credentials and must not be treated as authorization. Resolve them only after the gateway verifies scope and consumes the one-use grant. Gateway integration supplies credentials explicitly; there is no ambient credential lookup or automatic refresh. Do not fall back to environment credentials, cloud instance identities, developer login state, or default credential chains. Plans, grants, request fixtures, reports, and logs must not contain provider secrets. Keep retained bodies and resolver failures out of logs and assessment evidence.

## Provider adapter setup and limits

An operator must provision a separately authorized gateway and a credential profile for each approved scope before configuring a provider adapter. Bind the exact canonical HTTPS provider target, including its path, to the profile and signed request; an origin or hostname match alone is insufficient. The target must have a lowercase canonical host and no explicit port, user information, query string, fragment, percent escape, empty path component, or dot segment. Runtime policy also matches the provider-specific host and path plus the approved provider identity, region, and model. The provider target is independent of the gateway endpoint. Never derive a provider destination or credential reference from untrusted provider output. The adapter uses direct HTTPS with certificate and hostname validation; operators must also enforce the approved endpoint policy and gateway egress controls. Requests do not follow redirects, use ambient proxies, or retry automatically.

| Provider | Request mapping |
| --- | --- |
| OpenAI | Responses: text `input`, approved `model` and `max_output_tokens`, with `store: false` and `stream: false`. |
| Azure OpenAI | Responses: the same bounded text shape at `https://<resource>.openai.azure.com/openai/v1/responses`, without an API-version query parameter. |
| AWS Bedrock | Converse: one user text message and `inferenceConfig.maxTokens`. |
| Google Vertex AI | `generateContent`: one user text part and `generationConfig.maxOutputTokens`; project and region are bound to the target. |

Use only the supported text request and response shapes. Streaming, remote attachments, provider tool declarations, automatic tool execution, redirects, proxies, and automatic retries are unsupported. Extra request keys are denied even if a digest was approved. Requests and responses are bounded by the approved plan and gateway limits; the gateway response ceiling is 1 MiB, and transport deadlines bound connection, read, and total time. A limit violation or malformed response after a send does not establish that no provider work occurred.

To roll back, disable or remove the gateway's provider adapter and its endpoint-to-profile binding, revoke or rotate the affected scoped credential, and block gateway egress to that target. Preserve the replay store and shared budget ledger, including uncertain attempts, for reconciliation. Local rollback cannot cancel an already sent provider request or prove remote deletion; verify those outcomes independently.

## Budget, cancellation, and cleanup

Live assessment uses the shared `AssessmentBudgetLedger`; it must not create a parallel budget model.

The trusted controller passes an admitted agent attempt as `parent_attempt_id` and
may pass narrower `child_limits` to `execute_live_case`. The live plan and provider
response cannot select these values. Agent tools and provider calls must use the
same private engagement ledger so aggregate, subtree, fanout, depth, concurrency,
time, token, cost, and retained-output limits apply across both paths. A denied
child reservation prevents gateway dispatch. Restore this ledger after restart;
replacing it with an empty file could admit charges twice.

The safe order is:

1. Verify the signed grant and exact plan/request bindings without consuming the grant or reserving budget.
2. Reserve the approved worst-case amount in the shared ledger and require a newly `reserved` attempt.
3. Mark the attempt dispatched immediately before the gateway send.
4. Settle only from trustworthy outcome evidence, or mark the attempt uncertain.

A reservation may be released only when the gateway proves that no send occurred. After dispatch, a timeout, disconnect, cancellation, cleanup failure, process interruption, malformed response, or other unknown outcome leaves the attempt `uncertain` and retains the conservative reservation. Local cancellation and cleanup do not prove that a remote request stopped or that remote data was deleted.

The live runner bounds its wait for a dispatch by the smaller of the approved request time estimate and the remaining engagement or inherited parent/child deadline. A timed-out handler can still finish in the background; the runner does not treat the timeout as remote cancellation and cannot reuse that authorization. A production gateway transport must enforce its own network deadline and account for an in-flight request independently.

The gateway accepts at most 1 MiB of response bytes. The live plan must reserve no more than that limit for each response, and the runner rejects an actual response larger than its approved reservation before parsing it. A response-size overrun after dispatch leaves the attempt uncertain and charged.

## Evidence, tool proposals, and billing

Public results and retained evidence contain redacted metadata and digests only. They must not expose provider response text, raw response bodies, or tool-argument JSON. In v2 emulator evidence, a supported synthetic tool call can only be an inert proposal: the runner rejects names outside the plan allowlist and never executes it without a separate authorization path. V3 production adapters reject provider tool calls, non-text content, and unknown output instead of emitting a proposal.

Provider, emulator, or gateway usage and cost fields are estimates or unverified observations. Missing or partial usage never lowers the reservation automatically. A cost may be labeled reconciled only after a separate trusted process verifies an independent provider billing export, invoice, or equivalent billing record. A gateway-reported amount is not independent billing evidence.

## Residency, retention, and deletion

The approved provider scope pins the account or project and region. Before production use, operators must verify the complete gateway-to-provider data path, applicable residency controls, provider and gateway retention, deletion behavior, and evidence redaction. Requests must explicitly disable provider retention where the provider supports that setting.

Current fixtures and responses are synthetic. They demonstrate contract handling only and do not establish provider residency, non-retention, deletion, or privacy behavior.

## Production evidence gate

Production enablement is an operational decision and remains prohibited until evidence for the exact deployed revision demonstrates all of the following. The repository's policy and worker digests bind approved identifiers but do not verify evidence freshness and do not implement a deployment enablement switch:

- gateway-only egress from the isolated worker, with direct provider egress denied;
- deployed mTLS and SPIFFE worker authentication and exact gateway-origin pinning;
- protected signing-key custody, gateway-owned scoped credential custody, and rotation procedures;
- durable one-use authorization enforcement under concurrency and restart;
- shared-budget reservation, uncertain accounting, cancellation, and cleanup behavior under failure;
- verified provider scope, residency, retention, deletion, redaction, and independent billing reconciliation; and
- engagement approval for the exact plan, request digests, tool allowlist, budget, worker, gateway, and provider scope.

Disposable endpoint-independent tests can exercise adapter mapping and transport behavior; emulator tests exercise protocol validation, replay handling, conservative accounting, and redacted evidence. Neither proves that a production worker, gateway, credential resolver, provider, or billing system satisfies these controls. Live provider qualification remains blocked without real authorized endpoints and accounts. These tests do not close Issue #150 or Epic #77.

The existing worker supervisor documents a deployed `GET`/`HEAD` operation path. The v2 broker-backed POST path and v3 production dispatcher and adapters are validated only with synthetic or controlled transports; they have not been exercised on a production worker, gateway, credential resolver, or provider account. Review and verify that integration at its exact deployed revision before enabling a real canary. Verify the intended worker's SSH host key, isolation, authority service, egress policy, and gateway identity independently.
