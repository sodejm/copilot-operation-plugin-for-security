# Isolated Worker and Approval Store Specification

## Title
COPS Isolated Execution Worker and Approval State Store (`[E02.02]`)

## Overview
Defines fail-closed verifier inputs, worker capability attestation, an
ACID-compliant approval state store, and the process boundaries required to
dispatch authorized `cops.action-plan/v1` operations.

## Architectural Boundaries

1. **Independent Verification Inputs**:
   - Operator provisioning supplies a signed authorization, trust store, active
     Engagement, and approval store to a separate approval authority. The worker
     receives only the authorization identifier, current Action Plan, and its
     owner-provisioned capability inventory.
   - The verifier validates the signature, full signed snapshot, key and engagement
     windows, operator identity, engagement identifier, and expected worker before
     approval registration or consumption.
   - HMAC is shared-key channel authentication: a holder of the verifier secret can
     also mint authorizations. The execution worker must not hold that secret or an
     approval registration capability. The system does not claim non-repudiation.

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

4. **Separate Approval Authority and Worker**:
   - The approval authority owns verifier secrets, the protected store, and the
     consume-only Unix socket. Operator provisioning runs outside the execution
     worker and cannot be invoked by a worker request.
   - The authority accepts only a bounded, versioned request containing an
     authorization identifier, request identifier, exact Action Plan, and expected
     worker identity. The client closes its write side after the single JSON line;
     the authority reads through EOF and rejects trailing bytes before consumption.
     It verifies the stored signed authorization against those values and the active
     Engagement, then atomically persists the request identifier, exact request
     bindings, durable receipt, and authorization consumption. It does not accept a
     caller-supplied authorization envelope for registration.
   - After an ambiguous transport failure, the client retries once with the same
     request identifier. An exact retry returns the durable receipt from the first
     committed request; reuse with altered bindings fails closed.
   - A protected socket directory and socket permit only the designated worker
     account to connect. Linux peer credentials must match the configured worker
     UID, GID, and process identity; the worker verifies the authority UID. The
     authority account and worker account must differ. Insecure store or socket
     ownership and permissions fail closed.
   - A timeout or malformed, oversized, mismatched, forged, or altered replay cannot
     consume authority or block the authority indefinitely.

5. **Host Transport and Process Isolation**:
   - Remote requests use bounded versioned JSON over SSH with a pinned known-hosts
     entry and strict host-key verification. The request and response bind the exact
     host and worker identities; mismatches fail before execution.
   - Production execution requires a supported Linux sandbox with isolated
     process, filesystem, and network namespaces, a closed environment and file
     descriptor set, resource limits, and no-new-privileges. The worker checks
     readiness before consuming authority and refuses execution when a required
     isolation feature or protected path is unavailable.
   - Approval keys, store files, and authority sockets are never made available
     inside the tool sandbox. A worker or tool process cannot provision or mint an
     approval. Live destination and resource mediation remain a separate control
     tracked in issue #186.

6. **Bounded Dispatch Behavior**:
   - Commands use explicit argument arrays without shell interpolation.
   - External adapters require an operator-provisioned platform SHA-256 and verify
     their pinned upstream revision before operation dispatch. On Linux, the probe
     and operation use the same held staged inode through `/proc/self/fd`; other
     platforms fail closed when a substitution-resistant launch cannot be established.
   - Tool allowlists, wall-clock timeouts, aggregate raw output byte limits,
     operation-count limits, and ephemeral workspace cleanup remain enforced.
     Collection terminates the process group on timeout or overflow, normalizes both
     to `partial`, suppresses every retained raw prefix before redaction or
     persistence, and preserves non-zero tool exits as `failed`. Suppression is
     required because a timeout or byte boundary can split an arbitrarily long
     credential or configured secret.
   - Before invoking a non-inert adapter, the worker reserves a unique evidence
     inode relative to verified directory descriptors without following symbolic
     links. It refuses dispatch when reservation fails and revalidates the inode
     before writing so a repeated run cannot overwrite prior evidence or execute
     without a writable evidence destination.
   - Evidence remains within the aggregate artifact bound and reports both persisted
     size and post-redaction truncation separately from redaction. Truncation changes
     an otherwise successful result to `partial` with exit code `125`.
   - Deterministic `cops.run-result/v1` records include exit status and output hashes.
   - The Linux sandbox does not mediate approved live network egress (#186).
     Deployments must isolate the worker UID from untrusted same-UID processes
     that could modify staged executables or held descriptors outside the sandbox.

7. **Linux Production Isolation**:
   - Production adapter execution uses a fresh bubblewrap namespace as a dedicated
     non-root worker account. The sandbox exposes only the private operation
     workspace and required read-only runtime paths, clears the inherited
     environment, drops capabilities, and does not inherit unrelated descriptors.
   - The worker fails closed before approval consumption when bubblewrap, user
     namespaces, the configured worker identity, a private workspace, or a required
     kernel control is unavailable. Capability descriptors remain rejected until
     the sandbox has an explicit mapping for each one.
   - Kernel enforcement includes `NoNewPrivs`, address-space, process-count, CPU,
     file-size, open-file, and core-dump limits. Each launch receives new network
     and PID namespaces, and an untrusted adapter cannot create a raw network socket.
   - A required Ubuntu integration gate executes bubblewrap rather than mocking the
     process boundary. It verifies environment filtering, host-path and descriptor
     confinement, namespace separation, kernel limits, and fail-before-consume
     readiness behavior. Missing bubblewrap or disabled user namespaces fails that
     gate instead of reducing coverage.
