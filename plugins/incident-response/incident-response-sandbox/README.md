# COPS Incident Response Sandbox

This portable package creates typed incident plans and executes two low-risk
actions against **synthetic local JSON fixtures only**: `isolate-host` and
`revoke-session`. There is no production API adapter.

Use a private directory (`0700`) for plans, receipts, and a copied fixture.
The fixture file should be `0600`. Generate a plan with an expiry and unique
nonce, then save the output as `plan.json`:

```sh
python3 scripts/ir.py plan --action isolate-host --tenant example-tenant --target host-1 --expires-at 2030-01-01T00:00:00Z --nonce example-1 --approver-assertion analyst-1
python3 scripts/ir.py dry-run plan.json fixture.json > receipt.json
python3 scripts/ir.py execute plan.json receipt.json fixture.json
```

The second command is mandatory. Execution rejects expired or modified plans,
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
