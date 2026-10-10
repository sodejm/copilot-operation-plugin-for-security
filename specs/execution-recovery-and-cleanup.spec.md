# Specification: Execution Recovery and Cleanup Receipts (E02.06)

## Purpose

Enforce predictable, failure-resilient recovery, side-effect accounting, and cleanup verification across the COPS worker execution runtime. Ensures that interruption or failures never result in silent partial state drift, unauthorized automated replay of non-idempotent operations, or unrecorded residual operational artifacts.

## Invariants

1. **Side-Effect Accounting**: Every resource modification or temporary artifact produced during execution is recorded in an ownership-aware, append-only `SideEffectLedger`.
2. **Boundary & Ownership Protection**: Cleanup managers verify worker identity ownership and filesystem boundaries (confined within authorized worker workspace) before executing deletion. Out-of-bounds resources are never deleted and are recorded in `unresolved_effects`.
3. **Anti-Replay Resilience**: Injected failures after approval envelope consumption leave the authorization envelope in terminal `consumed` state in the `ApprovalStore`, guaranteeing that execution authorizations cannot be replayed.
4. **Interruption & Non-Idempotence**: Interruptions occurring during non-idempotent operations transition the run result to `uncertain` with an explicit reason, preventing automated retries.
5. **Verifiable Audit Receipt**: Rollback operations emit a canonical `cops.cleanup-receipt/v1` or `v2` document, whose SHA256 digest is cryptographically bound into `RunResult.evidence_records`. The receipt includes cleanup actions already committed to the durable ledger before rollback. V2 reports only quarantine locations that still exist; v1 remains unchanged for older readers.
6. **Durable Cleanup Journal**: Before approval consumption, the worker records the run intent in an owner-only append-only journal outside the execution workspace. It then records each side effect, cleanup attempt, terminal cleanup transition, and cleanup receipt. A side effect is not launched unless its cleanup intent is durably recorded first.
7. **Restart-Safe Recovery**: Worker startup safely reassesses unresolved filesystem effects while reporting, without replaying, effects already recorded as cleaned. Cleanup attempts interrupted before a terminal journal transition become explicit `unknown` outcomes, and recovered process identifiers are never signalled because a PID can be reused after restart.
8. **Persistence Failure Accounting**: A failed journal write cannot be reported as successful cleanup. The emitted receipt records the affected effect or audit record as unresolved and uses `partial` or `failed` status.
9. **Proven Ownership Required**: A cleanup declaration does not prove that the worker created its target. Plan-declared files and directories in a caller-supplied workspace, and plan-declared process identifiers in every workspace, remain unresolved and are never deleted or signalled without durable worker-created provenance. Restart recovery also preserves replacement resources for these unverified plan declarations.
10. **Creation Identity Before Cleanup**: Before creating a worker-owned file or directory, including a default execution workspace or credential scratch directory, the worker durably records cleanup intent. It creates the final entry exclusively, derives `(device, inode, resource type)` from the still-open creation descriptor, verifies the path still names that object without following symbolic links, and durably records the identity before automatic cleanup is permitted.
11. **Race-Resistant Filesystem Cleanup**: Cleanup resolves each path through verified parent directory descriptors, compares the current object with the durable creation identity, moves a matching object into an owner-only same-parent quarantine, and verifies the moved object again before descriptor-relative deletion. A replacement detected before or after quarantine remains present at its original path or in quarantine and is recorded as `unknown`. Rollback filters terminal effects before bounded ordering of actionable effects, with filesystem children ordered before their parents. Recursive directory cleanup is permitted only after every ledger descendant has a durable `cleaned` state; otherwise the directory is preserved and recorded as `unknown`.
12. **Unknown Preservation and Migration**: Missing resources, unverified creation outcomes, identity mismatches, interrupted cleanup attempts, and filesystem effects recovered from older journals without creation identity remain unresolved. Recovery never infers ownership from a path, filename, declared resource type, or cleanup action.

## Journal upgrade and rollback

New cleanup journals begin at metadata version 1. The first creation-identity
event or v2 receipt promotes the journal to version 2 in the same SQLite
transaction as the event. Existing version 1 journals and receipts remain
readable. Stop older workers before upgrading a journal: a version 1 reader
rejects version 2 metadata. If reverting the worker, preserve the version 2
journal and reconcile it with a version 2-capable worker; do not relabel or
truncate it to make an older worker accept it. Start a separate version 1
journal only for new work under the older worker.

## Filesystem identity limits

The durable identity is the portable POSIX tuple `(device, inode, resource type)`.
The quarantine-and-reverify sequence closes the path replacement window between
identity comparison and deletion for ordinary concurrent replacement. Filesystems
can reuse inode numbers, however, and a hostile process sharing the worker account
can interfere with owner-only state. Creation timestamps are not a portable,
immutable discriminator, and a worker-set pathname marker would have the same
replacement problem. Deploy the worker under a dedicated account and treat any
quarantined or unresolved resource as requiring operator reconciliation; the
identity tuple does not establish an absolute guarantee against inode reuse or a
hostile process with the same privileges.
