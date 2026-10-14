# Operator provider gateway boundary

The provider gateway is an opt-in execution boundary for an approved AI provider
canary. The repository implements a versioned, bounded `POST` broker contract
and an emulator for signed, one-use dispatch grants. It does not provision a
gateway, provider credentials, a production worker route, or a live provider
account. Repository tests establish protocol behavior only.

## Dispatch authority

Keep the operator's dispatch signing key outside the worker, gateway request,
plan, and evidence. Provision the gateway verifier with the corresponding
public key through an owner-protected trust store and a durable, owner-protected
replay store. The operator must approve a separate dispatch grant for each
request. It binds the action plan ID and digest, authorization ID, worker SPIFFE
identity, exact provider, account or project, region, model, gateway endpoint
ID, request target, body SHA-256 digest and byte count, and a short validity
window. The gateway verifies the signature, scope, body, worker identity, and
expiry, then consumes both the dispatch ID and authorization ID before a provider
handler runs. A reused ID or an unavailable replay store denies dispatch. The
replay store must enforce uniqueness for both IDs; legacy stores without the
authorization ID column fail closed until migrated with their consumption history
intact. Do not retry an uncertain dispatch with the same or a new ID until its
effect and charge are reconciled.

The worker-side broker permits one bounded `POST` only to the configured HTTPS
gateway origin and exact path. TLS must authenticate the hostname and configured
gateway SPIFFE resource identity. Redirects, automatic retries, direct provider
destinations, changed DNS destinations, oversized bodies, and body digest
mismatches are denied. The gateway is responsible for provider credentials;
the worker and assessment report must never receive their values. A gateway
implementation must independently compare the grant with its configured
provider endpoint and credential scope before calling the provider. This
repository's gateway emulator exercises that check without issuing a real
provider request. By default it has no credential resolver or provider transport.
An operator may install the local `GatewayScopedProviderHandler` in the emulator
with an exact endpoint-to-credential-reference binding, resolver, and synthetic
transport. It resolves the credential only after scope verification and one-use
grant consumption. The supplied transport still needs its own TLS, IAM, and
destination enforcement before any production use. Emulator handlers may return a
bounded JSON response only after the grant is consumed. Dispatch receipts hide
request and response bodies in their printed representation; operators must keep
any retained body and credential resolver failures out of logs and assessment
evidence. The gateway raises a generic error without preserving the underlying
provider exception chain.

## Operational controls before a real canary

1. Provision a separate gateway service account, authenticated TLS identity,
   trusted dispatch keys, durable replay storage, and provider credential
   resolver. Restrict each credential to the approved account or project,
   region, endpoint, model, and least privilege supported by that provider.
   Prevent gateway logs, errors, and traces from retaining secrets, prompts,
   canary text, provider output, or raw authorization envelopes.
2. Independently verify the production worker, SSH host key, isolation,
   authority service, egress policy, gateway identity, and credential scope on
   the intended host. The existing worker supervisor documents its deployed
   `GET`/`HEAD` operation path; a production `POST` operation must be wired to
   the v2 broker and reviewed at its exact revision before it can be enabled.
3. Approve the engagement, a bounded canary and its request digest, the exact
   provider scope, a shared budget, data residency, provider retention, and
   deletion terms. Use synthetic data in emulator runs. A real canary requires
   separate engagement authorization and exact-revision security review.
4. Record cancellation request, observed remote stop, any remaining provider
   operation, and cleanup independently. Cancellation of a local call does not
   prove that the provider stopped processing or billing. Retain uncertain
   reservations until independently reconciled. Verify provider-side deletion
   or retention through provider evidence; local file cleanup proves only local
   cleanup.
5. Compare provider usage and invoices or billing exports against the local
   reservation ledger. A response usage field is an estimate or unverified
   observation, not independently reconciled billing. Keep cost and final
   consumption pending when that evidence is absent.

The operational gate remains closed until these deployment and review records
exist for the exact worker, gateway, provider scope, and revision. The emulator
does not establish production readiness or a paid billing outcome.
