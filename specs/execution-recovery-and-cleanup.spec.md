# Specification: Execution Recovery and Cleanup Receipts (E02.06)

## Purpose

Enforce predictable, failure-resilient recovery, side-effect accounting, and cleanup verification across the COPS worker execution runtime. Ensures that interruption or failures never result in silent partial state drift, unauthorized automated replay of non-idempotent operations, or unrecorded residual operational artifacts.

## Invariants

1. **Side-Effect Accounting**: Every resource modification or temporary artifact produced during execution is recorded in an ownership-aware, append-only `SideEffectLedger`.
2. **Boundary & Ownership Protection**: Cleanup managers verify worker identity ownership and filesystem boundaries (confined within authorized worker workspace) before executing deletion. Out-of-bounds resources are never deleted and are recorded in `unresolved_effects`.
3. **Anti-Replay Resilience**: Injected failures after approval envelope consumption leave the authorization envelope in terminal `consumed` state in the `ApprovalStore`, guaranteeing that execution authorizations cannot be replayed.
4. **Interruption & Non-Idempotence**: Interruptions occurring during non-idempotent operations transition the run result to `uncertain` with an explicit reason, preventing automated retries.
5. **Verifiable Audit Receipt**: Rollback operations emit a canonical `cops.cleanup-receipt/v1` document, whose SHA256 digest is cryptographically bound into `RunResult.evidence_records`.
6. **Durable Cleanup Journal**: Before approval consumption, the worker records the run intent in an owner-only append-only journal outside the execution workspace. It then records each side effect, cleanup attempt, terminal cleanup transition, and cleanup receipt. A side effect is not launched unless its cleanup intent is durably recorded first.
7. **Restart-Safe Recovery**: Worker startup safely reassesses unresolved filesystem effects while skipping effects already recorded as cleaned. Cleanup attempts interrupted before a terminal journal transition become explicit `unknown` outcomes, and recovered process identifiers are never signalled because a PID can be reused after restart.
8. **Persistence Failure Accounting**: A failed journal write cannot be reported as successful cleanup. The emitted receipt records the affected effect or audit record as unresolved and uses `partial` or `failed` status.
9. **Proven Ownership Required**: A cleanup declaration does not prove that the worker created its target. Plan-declared files and directories in a caller-supplied workspace, and plan-declared process identifiers in every workspace, remain unresolved and are never deleted or signalled without durable worker-created provenance. Restart recovery also preserves replacement resources for these unverified plan declarations.
