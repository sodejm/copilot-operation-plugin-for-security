# Opt-in provider gateway contracts and adapters (E16.02)

## Scope and prerequisites

The separately versioned live plan requires explicit paid-execution opt-in,
an engagement budget, an approved canary and canonical request digest, exact
provider identity, region, endpoint and model, a tool allowlist, a configured
gateway HTTPS origin and path, SPIFFE worker identity, and a signed one-use
dispatch grant. The executable scenarios exercise a local emulator, a
broker-backed synthetic transport, the production dispatcher and registered
provider adapters against controlled transports, and four provider-shaped
synthetic envelopes without provider calls or real credentials. The existing
offline fixture command and schema remain unchanged.

Live plans use the existing provider IDs `openai`, `azure`, `aws`, and `gcp`.
The gateway credential handler maps those IDs to its configured transport
keys `openai`, `azure_openai`, `bedrock`, and `vertex` after verifying the
signed provider scope. Credentials remain gateway owned.

## Version and signed scope

`cops.ai-provider-live-assessment-plan/v2`,
`cops.ai-provider-live-assessment-cases/v2`, and
`cops.operator-gateway-dispatch/v2` remain schema-readable for historical
emulator evidence. Their closed field sets are preserved. They are ineligible
for production dispatch, including when the caller supplies a production
dispatcher. Relabeling a v2 document as v3 cannot supply the required scope.

Version 3 uses the corresponding `/v3` identifiers. Each environment, case,
and grant requires `execution_class: production`, opaque `auth_profile_id`
and `credential_reference_id`, `transport_version`, `endpoint_policy_digest`,
and `worker_evidence_digest`. These identities refer to gateway configuration;
they cannot contain credentials, file paths, environment-variable references,
or URLs. The provider identity kind explicitly distinguishes `account`,
`tenant`, `project`, or `subscription` through `account_or_project_kind` and
its exact `account_or_project` value. Region and model remain explicit.
Unknown fields are rejected at every object boundary.

| Provider | Exact transport version | Production endpoint form |
| --- | --- | --- |
| `openai` | `openai-responses/v1` | `https://api.openai.com/v1/responses` |
| `azure` | `azure-openai-responses/v1` | `https://<resource>.openai.azure.com/openai/v1/responses` |
| `aws` | `bedrock-converse/v1` | `https://bedrock-runtime.<region>.amazonaws.com/model/<model>/converse` |
| `gcp` | `vertex-generate-content/v1` | `https://<region>-aiplatform.googleapis.com/v1/projects/<project>/locations/<region>/publishers/google/models/<model>:generateContent` |

`request_target` is the exact approved HTTPS URL. Schema validation rejects
uppercase hosts, ports, user information, query strings, fragments, percent
encoding, empty path segments, and dot segments. Runtime endpoint policy must
also verify the provider-specific host, path, identity, region, and model;
lexical validity alone does not allow a destination. Azure uses an `api-key`
header at the gateway and has no API-version query parameter; the signed
transport version selects the protocol.

Each v3 grant signs the exact positive `body_bytes` and `body_sha256`, the
`plan_digest` and worker identity, and positive `max_output_tokens`,
`max_response_bytes`, and `max_elapsed_ms`. The response ceiling is 1 MiB.
These ceilings constrain the actual request and transport; estimates cannot
replace them. The policy and worker digests bind the approved endpoint policy
and worker readiness evidence. A schema validates shape, not signatures,
cross-document equality, evidence freshness, or execution authorization.

## Admission and dispatch order

1. Strictly validate the live plan and cases. Only text canary request shapes
   for OpenAI Responses, Azure OpenAI Responses, Bedrock Converse, and Vertex
   `generateContent` are admitted. The exact canonical request bytes, body
   size and digest, model, output cap, endpoint, and approved canary must match.
   Tool declarations, remote attachments, streaming, storage, unknown fields,
   direct provider egress, and unapproved provider paths are denied.
2. For production, reject v2 and any nonproduction execution class before
   reservation, credential resolution, or send. Derive expected grant values
   from the approved plan and request, and perform
   non-consuming signature, expiry, worker identity, gateway origin and path,
   gateway endpoint, and provider-scope verification. The gateway independently
   checks these values.
   Exact-compare every provider identity, auth reference, execution class,
   transport version, endpoint, digest, and request budget across approved
   plan, case, grant, and runtime configuration. Caller-supplied time or claimed
   gateway origin cannot satisfy this check.
3. Atomically reserve the approved worst-case amount in the shared
   `AssessmentBudgetLedger`, then mark the attempt dispatched immediately
   before consuming its one-use grant and invoking the approved gateway
   handler. A failed preflight does not reserve or send. An exhausted budget
   does not send.
4. A consumed grant cannot be replayed. Ambiguous send, timeout, disconnect,
   cancellation, malformed or partial response, and unavailable usage retain
   a conservative uncertain reservation. Gateway responses are capped at 1 MiB;
   a response larger than its approved byte reservation is rejected before
   parsing and remains uncertain. Automatic retry is forbidden.

## Results and operational limit

V2 emulator tool-use output is a proposal only and is never executed. V3
production adapters reject tool-use, non-text, and unknown output rather than
returning a proposal. Public
evidence contains normalized outcome, state, pseudonymous case reference,
digest and estimated cost; it excludes prompt, response content, tool
arguments, account, endpoint, canary, and credentials. Gateway or provider
reported usage is not independently reconciled billing. Local cancellation
and cleanup receipts do not prove remote cancellation or deletion.

Production use requires exact-revision evidence for an isolated worker,
gateway-only egress, mTLS/SPIFFE identity, protected grant signer and durable
replay state, gateway-owned scoped credentials, residency and retention,
independent billing reconciliation, and separate engagement authorization.
The emulator and controlled adapter tests do not establish these properties.

## Acceptance scenarios

The executable scenarios in
[`features/ai_provider_live_gateway.feature`](features/ai_provider_live_gateway.feature)
cover v3 required scope and budgets, unknown-field rejection, historical v2
readability and production-contract ineligibility, endpoint aliases, four
emulator provider envelopes, changed scope or identity, grant replay, direct
egress denial, budget exhaustion, uncertain and partial results, cancellation,
cleanup, tool proposals, and evidence redaction. Focused transport tests cover
the four registered production adapter mappings and controlled HTTPS endpoint
laboratories. Package validation and `make check` run in the repository virtual
environment.
Schema scenarios establish contract eligibility only. Production dispatch
tests must separately establish fail-closed version admission, signature and
scope matching, and enforcement of each transport budget before any live
qualification can be claimed.

## Threat and abuse cases

An attacker may present a forged or replayed grant, substitute another worker,
gateway, tenant, region, model, endpoint, canary or request body, include a
provider-hosted tool or attachment, understate the estimate, or omit usage
after a possible send. Exact plan/grant binding, independent gateway state,
narrow request shapes, shared budget admission and conservative uncertainty
limit those paths. A modified same-authority checkout or missing production
network controls can bypass the local boundary implementations; no real
containment claim follows from these local tests.
