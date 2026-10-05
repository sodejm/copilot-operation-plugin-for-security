# Specification: Execution Recovery and Cleanup Receipts (E02.06)

## Purpose

Enforce predictable, failure-resilient recovery, side-effect accounting, and cleanup verification across the COPS worker execution runtime. Ensures that interruption or failures never result in silent partial state drift, unauthorized automated replay of non-idempotent operations, or unrecorded residual operational artifacts.

## Invariants

1. **Side-Effect Accounting**: Every resource modification or temporary artifact produced during execution is recorded in an ownership-aware, append-only `SideEffectLedger`.
2. **Boundary & Ownership Protection**: Cleanup managers verify worker identity ownership and filesystem boundaries (confined within authorized worker workspace) before executing deletion. Out-of-bounds resources are never deleted and are recorded in `unresolved_effects`.
3. **Anti-Replay Resilience**: Injected failures after approval envelope consumption leave the authorization envelope in terminal `consumed` state in the `ApprovalStore`, guaranteeing that execution authorizations cannot be replayed.
4. **Interruption & Non-Idempotence**: Interruptions occurring during non-idempotent operations transition the run result to `uncertain` with an explicit reason, preventing automated retries.
5. **Verifiable Audit Receipt**: Rollback operations emit a canonical `cops.cleanup-receipt/v1` document, whose SHA256 digest is cryptographically bound into `RunResult.evidence_records`.
