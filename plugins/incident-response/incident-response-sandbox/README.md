# COPS Incident Response Sandbox

This portable package creates typed incident plans and executes two low-risk
actions against **synthetic local JSON fixtures only**: `isolate-host` and
`revoke-session`. There is no production API adapter.

## Usage and playback

Use a private directory (`0700`) for plans, receipts, and a copied fixture.
The fixture file should be `0600`. The self-contained operator playback generates
fresh expiry times, exercises plan, dry-run, execution, replay and expiry
rejection, and rollback, then removes its temporary state:

```sh
python3 plugins/incident-response/incident-response-sandbox/scripts/run_demo.py
```

See the [operator playback](docs/PLAYBOOK.md) for the manual artifact-preserving
commands, expected fields, contract definitions, reruns, and cleanup.

## Design and data flow

Execution rejects expired or modified plans,
tenant or target mismatch, changed state, stale dry-run receipts, missing fixture
permission, throttling, and duplicate plan hashes or nonces. Simulated partial
failure records whether rollback succeeded or failed. The fixture execution
history prevents replay of recorded attempts.

Each execution result and fixture history record include a deterministic
`provider_request_id` for the synthetic fixture operation and a
`post_action_verification` object. Available verification reports `succeeded`
or `failed` with a content-addressed fixture-state reference. When the fixture
sets `verification_available` to `false`, the result is `unavailable` and the
reference is `null`. The generated values contain only fixed labels and SHA-256
digests; do not replace them with credentials, bearer tokens, signed URLs, or
other secret provider response data. These fields demonstrate the receipt
shape against a local fixture; they are not evidence from a live provider.

| Contract or artifact | Purpose | Key fields | Producer | Consumer | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- |
| Typed plan | Bind one synthetic action to a tenant, target, approval assertion, and expiry | Plan ID, nonce, action, tenant, target, approver, expiry | Operator or playback | Dry-run and execution commands | Schema, action allowlist, expiry, and plan-hash checks | Isolate synthetic host `host-01` |
| Fixture state | Represent local provider state and execution history | Tenant, targets, sessions, throttling, verification, history | Playback fixture or operator copy | Synthetic executor | Private path, mode, tenant/target, and expected-state checks | Host starts connected |
| Dry-run receipt | Authorize the exact unchanged plan and fixture state for a later attempt | Plan hash, state reference, issued time | Dry-run command | Execution command | Freshness and exact plan/state binding | Receipt for one revoke-session plan |
| Execution result and history | Record attempted state change, verification, and replay marker | Outcome, provider request ID, verification, plan hash, nonce | Synthetic executor | Operator, rollback, and replay guard | Result schema, state digest, and unique plan/nonce checks | Session revoked and fixture digest recorded |
| Rollback result | Record whether simulated partial failure was restored | Original action, rollback status, error | Synthetic executor | Incident reviewer | Required after partial failure | Throttled isolation restored successfully |
| Playback summary | Qualify plan, dry-run, execution, replay, expiry, and rollback paths | Step results, rejection reasons, cleanup status | `scripts/run_demo.py` | Maintainer | Semantic assertions across success and failure paths | Replay and expired plan both rejected |

Follow the [end-to-end verification playbook](docs/VERIFICATION.md) to qualify this
package's documented workflow and prepare evidence for a maturity review.

## Retention expectations

Treat plans, receipts, and fixtures as incident records because their timing,
targets, and operator assertions may be sensitive even when the receipt fields
contain no secrets. Store them with least-privilege access and encryption where
required by the organization's approved incident-response, legal-hold, privacy,
and records-retention policies. Assign an owner and deletion or review date in
the system of record, preserve records subject to a legal hold, and securely
delete expired copies and temporary staging files. This package does not choose
a retention period or operate a records repository.

## Emergency-use expectations

Use this sandbox during an emergency only under an approved break-glass
procedure that names the authorizing role, allowed action and target, expiry,
evidence owner, and required after-action review. Continue to use a unique
nonce, explicit dry run, and private staging; record verification as
`unavailable` when it cannot be performed instead of treating the action as
verified. The package cannot grant emergency authority, bypass provider access
controls, contact a live provider, or attest that authorization occurred.

The approver name is an operator assertion. The plan hash detects accidental
or unauthorized changes to the plan content only when compared with a trusted
copy; it is not a signature, approval proof, or immutable audit record. This
package does not support concurrent writes by untrusted local accounts. Use
private staging on shared hosts. Production mutation and trusted approval
attestation remain separate work.
