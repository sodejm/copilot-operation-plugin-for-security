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

The approver name is an operator assertion. The plan hash detects accidental
or unauthorized changes to the plan content only when compared with a trusted
copy; it is not a signature, approval proof, or immutable audit record. This
package does not support concurrent writes by untrusted local accounts. Use
private staging on shared hosts. Production mutation and trusted approval
attestation remain separate work.
