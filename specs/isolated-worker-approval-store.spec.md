# Isolated Worker and Approval Store Specification

## Title
COPS Isolated Execution Worker and Approval State Store (`[E02.02]`)

## Overview
Provides a secure process isolation runtime boundary and ACID-compliant approval state store for executing authorized `cops.action-plan/v1` operations.

## Architectural Boundaries

1. **Separation of Control, Storage, and Tool Processes**:
   - Operator approval credentials and storage access are completely decoupled from unprivileged execution worker credentials.
   - Workers cannot forge or sign approvals; they can only query, atomically consume, and execute approved plans.

2. **Durable Approval State Store**:
   - Concurrency-safe SQLite engine configured with Write-Ahead Logging (`WAL`) mode and immediate transactions (`BEGIN IMMEDIATE`).
   - Prevents race conditions or double-spending among parallel worker processes.
   - Enforces filesystem permission checks (restricted to owner `0700` directory and `0600` database file on POSIX systems).

3. **Process Sandboxing & Resource Capping**:
   - Execution occurs within unprivileged boundaries (rejects root execution by default).
   - Commands are launched strictly via argument arrays (`subprocess.run(cmd, check=False)`) without shell interpolation (`shell=True`).
   - Strict tool whitelists, wall-clock timeouts, output byte limits, and ephemeral workspace cleanup.
   - Deterministic `cops.run-result/v1` contracts emitted with SHA256 output hashes and exit status.
