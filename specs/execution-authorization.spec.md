# Execution Authorization Specification

## Title
COPS Cryptographically Bound Execution Authorization (`cops.execution-authorization/v1`)

## Overview
Replaces unkeyed checksum receipts (`schema_version: 1.0`) with operator-authenticated, descriptor-bound authorization envelopes (`cops.execution-authorization/v1`) tied to immutable action plans (`cops.action-plan/v1`).

## Invariants & Rules

1. **Immutable Binding**:
   - Every authorization envelope cryptographically seals:
     - `action_plan_id`
     - `plan_digest`
     - `engagement_id`
     - `operator`
     - `issued_at`
     - `authorized_until_utc`
     - `bound_parameters` (`specialist_id`, `target`, `operations_summary`, `limits`, `credential_references`, optional `worker_identity`)
     - `approval_mode`
   - Any alteration to the action plan operations, arguments, targets, limits, or credentials invalidates the verification.

2. **Rejection of Legacy Receipts**:
   - Legacy receipts (`1.0`) are retained as historical evidence only.
   - Any attempt to use legacy receipts to authorize execution raises `AuthorizationError` and emits `LegacyReceiptDeprecationWarning`.

3. **Atomic Consumption & Replay Prevention**:
   - Authorized execution envelopes can only be consumed once.
   - Transitions move strictly from `approved` -> `consumed`, `revoked`, or `expired`.
   - Replay attempts on consumed envelopes fail immediately.
