---
name: execution-recovery-and-cleanup
description: Manage execution cancellation, rollback recovery, side-effect ledgers, and cleanup receipts.
---

# Execution Recovery and Cleanup Skill

This skill enforces safe cancellation, interruption handling, ownership-aware resource rollback, and emission of verifiable cleanup receipts.

## Workflow

1. **Side-Effect Ledger Tracking**: Record all transient resources, files, and state mutations produced during action plan execution in an append-only, ownership-bound ledger (`SideEffectLedger`).
2. **Cancellation and Non-Idempotent Step Handling**: Handle operator cancellation, signals, and timeouts safely. When interrupted during a non-idempotent operation, record status as `uncertain` and prevent automated retries.
3. **Precondition and Ownership Verification**: Verify resource ownership and filesystem boundaries before executing rollback. Never modify or delete assets outside the authorized worker workspace.
4. **Cleanup Receipts and Audit Preservation**: Execute reverse-chronological rollback and emit a validated `cops.cleanup-receipt/v1` or `v2` document binding cleaned and unresolved effects into the execution audit trail. Use v2 when a preserved quarantine location must be reported.
