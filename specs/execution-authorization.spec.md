# Execution Authorization Specification

## Title
COPS Cryptographically Bound Execution Authorization (`cops.execution-authorization/v1`)

## Overview
Replaces unkeyed checksum receipts (`schema_version: 1.0`) with authenticated
authorization envelopes bound to complete immutable Action Plan snapshots
(`cops.action-plan/v1`), an expected worker identity, and an active Engagement.

## Invariants & Rules

1. **Independent Verifier Trust**:
   - Verification requires a `cops.authorization-trust-store/v1` document supplied
     independently from the Action Plan, authorization, and worker request.
   - Each trusted key declares `key_id`, `algorithm: hmac-sha256`,
     `operator_identity`, `valid_from_utc`, `valid_until_utc`, `status`, and
     `secret_env`.
   - Secret bytes are loaded only from the environment variable named by
     `secret_env`; plans, authorizations, Engagements, requests, and defaults cannot
     supply them.
   - HMAC authenticates a shared-key channel. Any verifier holding the key can mint
     a valid authorization, so this contract does not provide non-repudiation.

2. **Complete Immutable Binding**:
   - Every authorization signs the complete approved Action Plan snapshot and a
     required expected worker identity.
   - The snapshot includes plan, engagement, and scenario identifiers; target,
     specialist, and action details; every operation's tool name, exact version, and
     arguments; effects; cleanup; credential references; limits; sequential batch
     semantics; prerequisites; creation time; and plan digest.
   - Plan status remains a separate lifecycle field. A status transition does not
     rewrite the signed snapshot, and a terminal plan cannot be newly authorized or
     executed.
   - Any mismatch between the authorization, current plan, expected worker, or
     engagement invalidates verification.

3. **Identity and Validity Windows**:
   - The authorization operator and engagement identifier must match both the active
     key and active Engagement.
   - The authorization validity window must fit inside both the active key window and
     Engagement window.
   - Unknown, revoked, inactive, expired, or not-yet-active keys fail closed.

4. **Legacy, Forgery, and Tamper Rejection**:
   - Legacy receipts (`1.0`), unsigned records, and digest-only records are historical
     evidence only and cannot authorize execution.
   - Forged signatures, altered snapshots, mismatched identities, and expired
     authorizations fail before authority is consumed.

5. **Atomic Consumption and Replay Prevention**:
   - A verified authorization can be consumed only once, immediately before dispatch.
   - SQLite consumption uses an immediate transaction so concurrent workers cannot
     spend the same authorization twice.
   - Replay attempts fail even when the earlier execution failed after consumption.

6. **Lifecycle and Rotation**:
   - Authorization state transitions from `approved` to a terminal consumed, revoked,
     or expired state; a terminal authorization cannot return to `approved`.
   - Key rotation provisions a new environment secret and active key, overlaps trust
     while signers switch, drains or replaces old outstanding authorizations, then
     revokes the old key and removes its secret.
