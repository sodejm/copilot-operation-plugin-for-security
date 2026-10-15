---
layout: documentation
title: "Offline Research Execution"
description: "Provision and review the opt-in Linux profile for approved local research corpora."
---

# Offline Research Execution

`offline-research/v1` is an opt-in Action Plan profile for bounded, locally
provisioned research files. It uses the normal engagement, signed full-plan
authorization, one-use approval, verified worker inventory, and cleanup journal.
The profile is available through the Python execution API; it does not add a
general-purpose research command or network fetcher.

## Prepare the worker and plan

1. Provision a dedicated, unprivileged Linux worker with the production
   `LinuxBubblewrapSandbox`, its normal approval control, and a verified,
   owner-provisioned worker capability inventory. Keep the approval authority
   and its signing material outside the worker account. Do not configure a
   scope guard, credential resolver, or egress trust domain for this profile.
2. Provision each corpus as a regular file under real, non-symlink directories.
   Each file is limited to 1 MiB. Review its contents and SHA-256 separately
   from the worker, then include its unique name, absolute source path, and
   SHA-256 in `offline_research.corpora`. Keep private source content out of
   plans, logs, and committed fixtures. The worker copies each approved file
   into a private temporary workspace using held, non-following descriptors.
   Source opens are nonblocking so a substituted FIFO is rejected as a
   non-regular file without holding the worker indefinitely.
3. Bind `offline_research.profile` to `offline-research`, `version` to `v1`,
   `worker_identity` to the verified inventory identity, and
   `worker_inventory_sha256` to the canonical digest of that inventory. Use a
   `local:<identifier>` target, no credential references, and
   `limits.egress_allowed: false`. Operations may only use the credential-free
   `inert/print_status` fixture or `cat/read_local_corpus` with a filename of
   `corpus-<approved-name>`. The `cat` adapter requires the approved GNU
   coreutils 9.4 version and its executable SHA-256 in
   `cat_executable_sha256`. It accepts no URL, destination, proxy, side effect,
   cleanup request, or egress policy.
4. On the same Linux worker configuration, collect an independent, recent
   `LinuxBubblewrapSandbox.observe_offline_isolation` observation in a private
   workspace and put its digest and UTC observation time in the signed plan's
   `isolation_attestation`. The observation must be no more than five minutes
   old when the worker validates the request. Review and sign the complete
   plan through the normal authorization workflow; profile fields are part of
   the signed snapshot.

The worker validates the profile, corpus digests, adapter pin, and a fresh
sandbox observation before consuming approval. The observation checks a
separate network namespace, only the loopback interface, no non-loopback
routes, and no inherited socket descriptors. The worker repeats that boundary
measurement while each external adapter version probe and operation is held
before its executable starts. Missing controls, stale or mismatched
observations, changed files, and unsupported operations fail closed.

## Review the result and deployment boundary

The `cops.run-result/v1` offline research record includes the approved
isolation digest, the fresh preflight observation, per-invocation observations
with an explicit `matches_approved` value (including rejected observations),
the inventory and executable digests, and the staged corpus digests. Compare
those records with the signed plan and the worker's protected inventory before
accepting a result. Treat tool output and corpus content as untrusted data.

Repository unit and executable feature tests exercise preflight with synthetic
files and observations. They do not establish that a particular host actually denied
network access or protected the corpus mount, approval store, worker UID, or
cleanup journal. Before using real data, independently verify the deployed
Linux namespace and network policy, account separation, corpus provisioning,
and journal recovery. A worker process or host administrator sharing the
worker's authority can interfere with its local evidence. See the
[Authenticated Execution Guide](AUTHENTICATED_EXECUTION.md) and
[Security Model](SECURITY_MODEL.md) for the common approval and host controls.
