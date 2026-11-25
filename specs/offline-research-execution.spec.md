# Offline Research Execution Profile

## Scope

`offline-research/v1` is an opt-in Action Plan profile for reading approved,
locally provisioned corpora in an isolated Linux worker. It uses the existing
engagement, signed full-plan authorization, one-use approval control, worker
inventory, adapter pinning, evidence, and cleanup contracts.

## Invariants

1. The signed plan binds the profile and version, worker identity, digest of the
   independently provisioned worker inventory, each corpus name, source path and
   SHA-256, any external adapter executable digest, and the digest and time of a
   separately observed isolation boundary. Profile substitutions invalidate the
   signed plan. The worker compares these values with its trusted inputs before
   approval consumption.
2. Only `local:<identifier>` targets, credential-free inert status fixtures, and
   the pinned GNU `cat` adapter reading `corpus-<name>` files are allowed. The
   authority requires exact membership in the provisioned engagement's included
   targets. An exact exclusion overrides inclusion. This check uses local
   identifiers directly and performs no name resolution. The
   profile has no egress policy, side effects, cleanup request, credential grant,
   scoped network target, resolver, proxy, or mediator. Unknown adapters and
   destination-bearing arguments fail closed.
3. Before creating a workspace, writing a cleanup journal, or accessing any
   corpus, the worker asks the protected authority to verify the unconsumed
   authorization against the signed plan and the provisioned engagement. Corpora
   are bounded regular files under real directories. The worker reads them
   through non-following held descriptors, checks their approved digests, and
   stages private copies before one-time consumption. Consumption rechecks the
   authorization and requires the configured live observer evidence. Changes, symlinks,
   oversized files, and duplicate names fail closed.
4. On Linux, a fresh gated bubblewrap probe must observe
   only loopback, no non-loopback IPv4 or IPv6 route, no inherited socket file
   descriptors, and a network namespace separate from the host. The observation
   must match the approval-bound digest and be recent. Missing, stale, malformed,
   or mismatched observations fail before approval consumption. Each adapter
   version probe and execution is then held before its tool starts while the
   worker measures that actual sandbox process and compares its boundary digest.
   PID metadata alone is not readiness: before measuring, the worker must verify
   that the child is blocked reading the exact worker-owned execution gate pipe.
   Setup must finish within the existing execution deadline. Missing procfs
   evidence, an unsupported syscall ABI, or a different gate fails closed; a
   network channel at the gate is rejected without retrying the measurement.
5. The run result records the approved boundary digest, probe and per-invocation
   observations and their scope, worker inventory and adapter digests, and
   staged corpus digests. A network-denial claim for a deployment requires
   independent host observation of the OS boundary.
   Before cleanup, the worker retains finalized redacted output and evidence
   envelopes for delivery in the bounded SSH response. The client authenticates
   the response and verifies the bytes against the artifact paths, sizes, and
   SHA-256 digests in the result. If the artifacts cannot fit in the response,
   the result reports unavailable output and cannot report success.
6. Windows and macOS remain independently unsupported. The Linux sandbox rejects
   both readiness and execution on each host before process setup; it must not
   fall back to an unsandboxed process. Portable tests of those denials are not
   native isolation qualification. Enabling either host requires its own native
   enforcement and independent observer design, exact platform/runtime/revision
   evidence, and zero-skip native negative tests for the approval, network,
   filesystem, cancellation, and recovery boundaries above.

## Supervisor profile selection

The owner-only `cops.worker-supervisor-config/v2` configuration may select
`execution_profile: "offline-research/v1"`. Omitting the field, or selecting
`"standard"`, preserves the existing scoped worker construction. Unknown values
fail startup. Offline mode cannot configure an egress trust domain or credential
manifest and constructs no network scope guard, resolver or egress mediator.
The worker requires a signed `offline-research/v1` plan before any approval or
execution; removing the profile cannot select the standard path. All existing
inventory, corpus, adapter, observation, budget, engagement and cleanup checks
remain mandatory, including durable journal recovery before the receiver is
created. This configuration is not independent observer or deployment evidence.

## Abuse cases and limits

An attacker may substitute a corpus after review, swap a signed plan or receipt,
request a URL or DNS name through an adapter, reuse a stale boundary observation,
inherit a socket or proxy, or place a symlink in a corpus path. Each must fail
closed before execution or be explicitly identified as an unproven deployment
boundary. The worker's own measurements cover each sandbox before the tool runs;
they do not independently attest the host, image, network policy over time, or
the provenance of a host-mounted corpus. A dedicated worker UID and trusted host
provisioning remain required.
