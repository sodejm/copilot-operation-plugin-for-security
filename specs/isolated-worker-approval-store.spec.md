# Isolated Worker and Approval Store Specification

## Title
COPS Isolated Execution Worker and Approval State Store (`[E02.02]`)

## Overview
Defines fail-closed verifier inputs, worker capability attestation, and an
ACID-compliant approval state store for dispatching authorized
`cops.action-plan/v1` operations. Operating-system and process transport isolation
is a separate deployment boundary tracked in issue #185.

## Architectural Boundaries

1. **Independent Verification Inputs**:
   - Worker execution requires an authorization trust store, the active Engagement,
     the current Action Plan, the caller-supplied authorization, and a worker
     capability inventory.
   - The verifier validates the signature, full signed snapshot, key and engagement
     windows, operator identity, engagement identifier, and expected worker before
     approval registration or consumption.
   - HMAC is shared-key channel authentication: a holder of the verifier secret can
     also mint authorizations. The worker does not claim non-repudiation.

2. **Owner-Provisioned Worker Capability Attestation**:
   - `cops.worker-capability-inventory/v1` contains `worker_identity`, canonical UTC
     `measured_at`, `measurement_source`, exact `tool_versions`, and
     `platform_capabilities`.
   - The artifact is created independently by the worker owner from a trusted
     measurement or deployment process. COPS loads and compares it; COPS does not
     populate it through runtime host capability discovery. Per-launch executable
     verification is a separate dispatch control.
   - The loader requires a non-symlink regular file owned by the current user with no
     group or other permission bits. An optional expected worker assertion must match
     `worker_identity`.
   - Both `IsolatedWorker` and `LaboratoryHarness.execute_case` require inventories
     verified by the protected file loader. Directly constructed inventories are
     rejected before authorization registration, consumption, or adapter execution
     for positive, negative, and remediated laboratory cases.
   - `IsolatedWorker` accepts the inventory and derives an immutable runtime
     configuration from it; caller-supplied mutable capability configurations are
     not accepted.
   - Before consuming authority, the worker compares the signed tool versions and
     platform prerequisites with the inventory and enforces signed sequential batch
     semantics and operation limits.

3. **Durable Approval State Store**:
   - SQLite uses Write-Ahead Logging and `BEGIN IMMEDIATE` transactions to prevent
     concurrent double-spending.
   - Filesystem permissions restrict the state directory and database to the owner on
     POSIX systems.
   - Existing unsigned or digest-only rows migrate to `legacy-untrusted`, retain their
     historical status, and are returned through a separate read-only audit record
     representation; they remain non-executable.

4. **Bounded Dispatch Behavior**:
   - Commands use explicit argument arrays without shell interpolation.
   - External adapters require an operator-provisioned platform SHA-256 and verify
     their pinned upstream revision before operation dispatch. On Linux, the probe
     and operation use the same held staged inode through `/proc/self/fd`; other
     platforms fail closed when a substitution-resistant launch cannot be established.
   - Tool allowlists, wall-clock timeouts, aggregate raw output byte limits,
     operation-count limits, and ephemeral workspace cleanup remain enforced.
     Collection terminates the process group on timeout or overflow, normalizes both
     to `partial`, and preserves non-zero tool exits as `failed`.
   - Evidence remains within the aggregate artifact bound, reports truncation
     separately from redaction, and creates directories and files relative to
     verified directory descriptors without following symbolic links.
   - Deterministic `cops.run-result/v1` records include exit status and output hashes.
   - These application controls do not establish operating-system or process
     transport isolation (#185) or mediate live network egress (#186); deployments
     must provide those controls independently. The deployment must also isolate the
     worker UID because a hostile same-UID process can modify the staged executable
     inode or manipulate held descriptors.
