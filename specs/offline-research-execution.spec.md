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
   profile has no egress policy, side effects, cleanup request, credential grant,
   scoped network target, resolver, proxy, or mediator. Unknown adapters and
   destination-bearing arguments fail closed.
3. Corpora are bounded regular files under real directories. The worker reads
   them through non-following held descriptors, checks their approved digests,
   and stages private copies before consuming approval. Changes, symlinks,
   oversized files, and duplicate names fail closed.
4. On Linux, a fresh gated bubblewrap probe must observe
   only loopback, no non-loopback IPv4 or IPv6 route, no inherited socket file
   descriptors, and a network namespace separate from the host. The observation
   must match the approval-bound digest and be recent. Missing, stale, malformed,
   or mismatched observations fail before approval consumption. Each adapter
   version probe and execution is then held before its tool starts while the
   worker measures that actual sandbox process and compares its boundary digest.
5. The run result records the approved boundary digest, probe and per-invocation
   observations and their scope, worker inventory and adapter digests, and
   staged corpus digests. A network-denial claim for a deployment requires
   independent host observation of the OS boundary.

## Abuse cases and limits

An attacker may substitute a corpus after review, swap a signed plan or receipt,
request a URL or DNS name through an adapter, reuse a stale boundary observation,
inherit a socket or proxy, or place a symlink in a corpus path. Each must fail
closed before execution or be explicitly identified as an unproven deployment
boundary. The worker's own measurements cover each sandbox before the tool runs;
they do not independently attest the host, image, network policy over time, or
the provenance of a host-mounted corpus. A dedicated worker UID and trusted host
provisioning remain required.
