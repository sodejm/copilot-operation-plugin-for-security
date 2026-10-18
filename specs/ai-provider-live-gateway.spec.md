# Opt-in provider gateway emulator contract (E16.02)

## Scope and prerequisites

The separately versioned live plan accepts only explicit paid-execution opt-in,
an engagement budget, an approved canary and canonical request digest, exact
provider account or project, region, endpoint and model, a tool allowlist, a
configured gateway HTTPS origin and path, SPIFFE worker identity, and a signed
one-use dispatch grant. This contract exercises a local gateway emulator, a
broker-backed synthetic transport, and four provider-shaped synthetic
envelopes. It makes no provider call, obtains no
credential, and does not enable the production worker route. The existing
offline fixture command and schema remain unchanged.

## Admission and dispatch order

1. Strictly validate the live plan and cases. Only text canary request shapes
   for OpenAI Responses, Azure OpenAI Responses, Bedrock Converse, and Vertex
   `generateContent` are admitted. The exact canonical request bytes, body
   size and digest, model, output cap, endpoint, and approved canary must match.
   Tool declarations, remote attachments, streaming, storage, unknown fields,
   direct provider egress, and unapproved provider paths are denied.
2. Derive expected grant values from the approved plan and request, and perform
   non-consuming signature, expiry, worker identity, gateway origin and path,
   gateway endpoint, and provider-scope verification. The gateway independently
   checks these values.
   Caller-supplied time or claimed gateway origin cannot satisfy this check.
3. Atomically reserve the approved worst-case amount in the shared
   `AssessmentBudgetLedger`, then mark the attempt dispatched immediately
   before consuming its one-use grant and invoking the emulator. A failed
   preflight does not reserve or send. An exhausted budget does not send.
4. A consumed grant cannot be replayed. Ambiguous send, timeout, disconnect,
   cancellation, malformed or partial response, and unavailable usage retain
   a conservative uncertain reservation. Gateway responses are capped at 1 MiB;
   a response larger than its approved byte reservation is rejected before
   parsing and remains uncertain. Automatic retry is forbidden.

## Results and operational limit

Provider tool-use output is a proposal only and is never executed. Public
evidence contains normalized outcome, state, pseudonymous case reference,
digest and estimated cost; it excludes prompt, response content, tool
arguments, account, endpoint, canary, and credentials. Gateway or provider
reported usage is not independently reconciled billing. Local cancellation
and cleanup receipts do not prove remote cancellation or deletion.

Production use requires exact-revision evidence for an isolated worker,
gateway-only egress, mTLS/SPIFFE identity, protected grant signer and durable
replay state, gateway-owned scoped credentials, residency and retention,
independent billing reconciliation, and separate engagement authorization.
The emulator does not establish these properties.

## Acceptance scenarios

The executable scenarios in
[`features/ai_provider_live_gateway.feature`](features/ai_provider_live_gateway.feature)
cover four provider envelopes, changed scope or identity, grant replay,
direct egress denial, budget exhaustion, uncertain and partial results,
cancellation, cleanup, tool proposals, and evidence redaction. Focused tests,
package validation, and `make check` run in the repository virtual environment.

## Threat and abuse cases

An attacker may present a forged or replayed grant, substitute another worker,
gateway, tenant, region, model, endpoint, canary or request body, include a
provider-hosted tool or attachment, understate the estimate, or omit usage
after a possible send. Exact plan/grant binding, independent gateway state,
narrow request shapes, shared budget admission and conservative uncertainty
limit those paths. A modified same-authority checkout or missing production
network controls can bypass the emulator; no real containment claim follows
from these local tests.
