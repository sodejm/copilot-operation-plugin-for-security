# Incident response sandbox executor

## Scope

The portable package creates typed, expiring action plans for a named tenant and
target. Its executor writes only a synthetic local fixture. The package does not
connect to production services or establish that a named approver consented.

## Contract

- A plan binds its action, tenant, target, parameters, expected state, desired
  state, expiry, and unique nonce in a canonical SHA-256 digest.
- A successful explicit dry run yields a receipt bound to the plan digest and
  fixture revision. Execution requires that receipt and rechecks plan expiry,
  fixture revision, expected state, permissions, and replay history.
- Only `isolate-host` and `revoke-session` are valid fixture actions. The
  executor accepts no arbitrary command, URL, or production adapter selector.
- Duplicate and replayed plans fail. Permission denial and throttling fail
  closed. A simulated partial failure attempts rollback and reports separately
  whether rollback succeeded or failed.
- Each execution result records a deterministic fixture-provider request ID and
  post-action verification evidence. Available verification records a
  content-addressed fixture-state reference and reports whether the desired
  state was observed; unavailable verification records an `unavailable` result
  and no reference. These identifiers and references contain no fixture values
  or credentials.
- Plan hashes and approver names are self-recorded assertions, not approval
  attestation or immutable provenance.

## Boundaries

Production mutation and trusted approval attestation require separate designs.
Concurrent untrusted mutation of the local fixture is outside this sandbox
contract. Operators should use a private staging directory on shared hosts.
Receipt retention and emergency-use procedures remain governed by the
operator's approved incident-response and records policies.
