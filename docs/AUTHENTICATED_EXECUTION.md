---
layout: documentation
title: "Authenticated Execution"
description: "Configure verifier trust, bind approvals to immutable Action Plans and worker identity, and operate one-time execution authorization."
---

# Authenticated Execution

COPS separates planning, approval, and execution. A reviewed Action Plan is not execution authority by itself. The isolated worker accepts a plan only when an independent verifier validates a signed authorization against the full approved plan, the expected worker, and the active engagement, then atomically consumes that authorization.

This guide covers the operator-facing trust channel and lifecycle. The [Security Model](SECURITY_MODEL.md) explains the wider threat model, and the [Compatibility guide](COMPATIBILITY.md#5-authenticated-execution-compatibility-and-migration) separates repository proof from host and network guarantees.

## Trust artifacts and boundary

An authenticated execution uses five inputs with distinct responsibilities:

1. The **Engagement** defines the authorized operator, scope, and time window.
2. The **Action Plan** records the immutable approved operation details.
3. The **Execution Authorization** signs the full approved plan snapshot and the expected worker identity.
4. The **Authorization Trust Store** tells the verifier which signing keys and operators it trusts. It references secret-bearing environment variables but contains no secret bytes.
5. The **Worker Capability Inventory** is an independently provisioned measurement of one worker's exact tool versions and platform capabilities.

The authorization window must fit within both the active key window and the engagement window. Changing the plan, target, operations, arguments, limits, prerequisites, expected worker, or authorization timestamps after signing causes verification to fail.

## Configure verifier trust

Create a local JSON trust store for the verifier:

```json
{
  "schema_version": "cops.authorization-trust-store/v1",
  "keys": [
    {
      "key_id": "engagement-2026-q4",
      "algorithm": "hmac-sha256",
      "operator_identity": "operator-red-team-lead",
      "valid_from_utc": "2026-10-01T00:00:00Z",
      "valid_until_utc": "2026-12-31T23:59:59Z",
      "status": "active",
      "secret_env": "COPS_AUTH_KEY_2026_Q4"
    }
  ]
}
```

Keep the trust-store as a regular, non-symlink file owned by the verifier with no
group or other permissions (for example, mode `0600`) on POSIX systems. Active
entries require canonical `valid_from_utc` and `valid_until_utc` bounds. A revoked
entry remains loadable after its `secret_env` and environment secret have been
removed; revoked keys are never usable for verification.

Supply at least 32 bytes of signing material through the named environment variable. Inject it from the operating system, process supervisor, or approved secret manager. Never put secret bytes in the Action Plan, Execution Authorization, Engagement, worker request, command defaults, logs, fixtures, or committed trust-store file.

HMAC provides shared-key channel authentication. Every verifier with the secret can also mint a valid authorization, so this design does not provide non-repudiation or independent signer identity proof. Limit secret access to the verifier boundary, record who can read it, and rotate the key when that membership changes.

## Supply planner tool-version provenance

Before compiling an Action Plan, measure the scenario operation tool through an independently trusted inventory or deployment workflow. Pass each exact value to the CLI with repeatable `--tool-version TOOL=VERSION` options, or pass the required `tool_versions: Mapping[str, str]` argument to `build_action_plan` or `run_engagement_plan_workflow`. For example:

```bash
python3 -m cops engagement plan \
  --engagement engagement.json \
  --scenario COPS-E03.01-S01 \
  --target 10.100.0.10 \
  --tool-version python3=3.11.9 \
  --output action-plan.json
```

The planner records the supplied exact version in the immutable operation. It does not inspect installed executables or prove the measurement is accurate. Plan compilation rejects a missing or blank version for the scenario operation tool; the CLI also rejects malformed entries and conflicting repeated values for the same tool.

This planning input and the worker capability inventory have independent provenance. The planner caller supplies the version that reviewers approve and sign. The worker owner later provisions a measurement of the worker. Execution verifies that the signed plan's exact tool version matches that worker inventory; one artifact must not be derived from the other merely to make the comparison pass.

## Provision the worker capability inventory

The worker owner must measure and provision an inventory through a trusted deployment or host-measurement workflow:

```json
{
  "schema_version": "cops.worker-capability-inventory/v1",
  "worker_identity": "worker-lab-01",
  "measured_at": "2026-10-06T12:00:00Z",
  "measurement_source": "approved-host-baseline",
  "tool_versions": {
    "nmap": "7.94"
  },
  "platform_capabilities": [
    "raw-sockets"
  ]
}
```

`measured_at` must be canonical UTC and cannot be in the future. The loader accepts only a non-symlink regular file owned by the current user with no group or other permission bits; mode `0600` is the normal choice. Keep the measurement workflow and artifact distribution inside the worker owner's trusted boundary.

COPS loads and compares this owner-provisioned attestation. It does not populate
the inventory by discovering host capabilities, and it does not prove that the
recorded measurement is accurate. Re-measure and replace the artifact through the
trusted provisioning workflow whenever the worker's tools or platform capabilities
change. Separately, every external adapter launch verifies the selected executable's
platform digest and upstream version; that per-launch check does not turn the
inventory into a host-wide discovery or attestation mechanism.

Inspect a provisioned inventory without claiming execution readiness:

```bash
python3 -m cops worker status \
  --worker-inventory worker-capability-inventory.json \
  --worker-id worker-lab-01 \
  --json
```

`--worker-id` is an optional assertion against the inventory identity. The `inventory_loaded` status reports the recorded identity, versions, capabilities, measurement time, and source. It does not prove authorization, engagement scope, process isolation, egress mediation, or readiness to execute a particular plan.

## What the authorization covers

The signature covers the complete approved Action Plan snapshot and expected worker identity. The snapshot includes:

- plan, engagement, and scenario identifiers;
- target, specialist, and action details;
- operation tool names, exact tool versions, and arguments;
- effects, cleanup steps, and credential references;
- execution limits and explicit sequential batch semantics;
- platform prerequisites; and
- plan creation time and cryptographic digest.

Plan status is a separate lifecycle field and is excluded from the signed snapshot. Lifecycle transitions do not rewrite the signed snapshot; terminal states (`fulfilled`, `rejected`, and `cancelled`) cannot be newly authorized or executed.

## Execute once in an isolated worker

Provide the plan, its opaque authorization ID, the approved worker identity, and
the owner-protected SSH endpoint inventory:

```bash
python3 -m cops worker execute action-plan.json \
  --authorization auth-example-00000001 \
  --worker-id worker-lab-01 \
  --ssh-endpoint-inventory /etc/cops/ssh-endpoints.json \
  --json
```

The operator CLI treats `--authorization` as an opaque ID and sends the plan to the
endpoint selected by the exact `--worker-id` entry. Host, account, and forced-command
settings come only from the protected SSH inventory; they cannot be supplied as
command-line overrides. The operator host does not load verifier keys, the approval
database, the engagement, worker capability inventory, or adapter executable pins.
The [worker supervisor](WORKER_SUPERVISOR.md) runs under a separate unprivileged
account. It owns the worker inventory and execution inputs, checks plan scope and
isolation, and asks the independent approval authority to consume the authorization.
Only that authority account owns verifier keys, the trust store, and the approval
database; the worker account has consume-only access to its control socket.

Provision executable pins on that remote worker from the exact approved binary. For
example, on Linux:

```bash
tool_path="$(command -v nmap)"
tool_sha256="$(sha256sum "$tool_path" | cut -d ' ' -f 1)"
printf '%s  %s\n' "$tool_sha256" "$tool_path"
```

Record the package or worker-image source used to obtain the executable and refresh
the digest after every approved upgrade. A missing pin, a digest mismatch, a probe
whose captured version differs from the adapter's pinned upstream revision, or a
change in file identity fails closed before the operation starts. The adapter's
logical compatibility version and its upstream executable revision are distinct;
for example, an adapter can use logical version `coreutils-9.4` while its GNU echo
probe captures upstream revision `9.4`.

External adapter execution currently requires Linux with an executable
`/proc/self/fd` mount. The worker copies the source through a non-following file
descriptor into its private workspace, verifies the configured SHA-256 digest and
version, and launches the same held staged inode through `/proc/self/fd`. This binds
the probe and operation to one file identity even if the original pathname is
replaced. macOS `/dev/fd` does not provide the required executable-descriptor
behavior, so external launches fail closed there. The `inert` test operation remains
available without an executable pin. On non-POSIX hosts, plans containing only
`inert` operations use a fresh private temporary workspace and a portable evidence
reservation path. Each artifact is created exclusively, kept open through capture,
and checked against its reserved file identity where the operating system exposes
one; collisions never overwrite existing evidence, and symbolic links or Windows
reparse points are rejected where the platform exposes them.

Before consuming an approval, the worker also checks that every registered adapter
supports the worker environment and can assemble the approved operation, and that
the host supports descriptor-bound executable launch. The staged executable and
reserved evidence artifact retain their parent directory descriptors until cleanup
or capture; replacing a parent pathname cannot redirect the write or deletion.

Run the worker under a dedicated isolated account. Descriptor binding prevents
pathname substitution, but it does not defend against another process with the same
worker UID that can modify the private staged inode in place, manipulate its file
descriptor, or interfere with the process. The workspace and every parent component
must be real directories rather than symbolic links.

The worker rejects inventory identity mismatches, missing tools, logical adapter
version mismatches, missing platform capabilities, unsupported batch semantics, and
operation counts above the signed batch maximum before execution.

Library callers must pass the `WorkerCapabilityInventory` loaded by
`WorkerCapabilityInventory.from_file` directly to `IsolatedWorker`; caller-built
inventories and mutable `WorkerConfig` values are not accepted at the worker
boundary.

The independent approval authority consumes the authorization in a SQLite
transaction immediately before dispatch. A second attempt with the same
authorization fails as replay. Keep the approval database on durable storage owned
by the authority account and protect it with the same access controls as other
execution records.

When an operation needs a credential, configure a `ScopedCredentialResolver` with
operator-supplied exact grants and a credential provider. The worker follows this
order for each launch:

1. Validate adapter compatibility and probe executable identity and version with
   no credential environment.
2. Atomically consume the approval and keep the exact object returned by the
   approval store.
3. Immediately before an operation launch, pass that local consumed object, the
   approved plan, the worker identity, and the exact operation to the resolver.
4. Pass the returned environment only as the operation environment and share the
   resolver's redactor with evidence capture.

The resolver checks the plan digest, engagement, worker, target, step, tool, tool
version, and action against each exact grant. The plan credential references are
an allowlist: a step receives its exact grants, while a step without a grant is
credential-free even when another step uses a credential. Credential environment
names must use the `COPS_CREDENTIAL_` prefix, which prevents grants from replacing
runtime, loader, broker, locale, or ordinary process settings. Provider values are
rejected if they are empty, non-text, or contain a NUL byte. Provider errors are
rewritten without their message or exception chain. All resolved values are
registered for redaction before launch. Never use a status field on a
caller-constructed authorization as evidence of atomic consumption.

Stdout and stderr share the Action Plan's raw byte limit. The worker enforces that
limit while reading the pipes and terminates the process group on timeout or overflow.
After dispatch, a non-idempotent step has an `uncertain` outcome with exit code `124`
or `125` respectively and cannot be repeated automatically; an idempotent step is
`partial`. Collector or evidence failures after a non-idempotent dispatch also
produce `uncertain` so an operator can reconcile effects before any repeat. A normal
non-zero tool exit is `failed`. Evidence persistence applies the same remaining
aggregate bound after redaction; truncation is reported separately from redaction.
Artifact directories and files are created relative to verified directory file
descriptors and reject symbolic links or paths that escape the workspace.

Real execution evidence requires a complete `EvidenceContext`. The recorder emits
validated `cops.evidence/v1` envelopes with the plan identifier and digest,
authorization, engagement, worker, target, step, tool, tool version, and action.
Stdout, stderr, errors, artifact identifiers, and artifact content pass through the
same redactor before envelope validation or persistence. Artifact identifiers must
be safe logical or workspace-relative names; absolute, drive-qualified, empty, and
traversal components fail closed. A redaction or schema failure discards the
reservation and produces no record or artifact. Captured output is untrusted data,
so prompt-like text in a stream or artifact does not become an instruction.

Raw values remain in memory only for redaction and are prohibited from
persistence. Redacted artifacts use an owner-controlled workspace, private
directories, and `0600` files on POSIX systems. File permissions restrict access;
they do not encrypt evidence at rest. Use an encrypted filesystem or storage
service when the deployment requires encryption. COPS does not automatically
delete redacted evidence: the workspace owner must enforce the engagement's
retention and deletion schedule. The evidence lifecycle fields state these
implemented controls and the absence of automatic deletion; they are not a
substitute for an external retention job or encryption control.

## Validate in the scenario laboratory

The laboratory uses the same verifier trust and engagement inputs:

```bash
python3 -m cops lab run \
  --environment lab-environment.json \
  --plan action-plan.json \
  --authorization execution-authorization.json \
  --authorization-trust-store authorization-trust-store.json \
  --engagement engagement.json \
  --worker-inventory worker-capability-inventory.json \
  --case-type positive \
  --store approvals.sqlite3 \
  --output result.json
```

Library callers must load `WorkerCapabilityInventory` with `from_file`. The laboratory rejects directly constructed inventories before registering or consuming authorization or invoking an adapter, for every case type.

The laboratory asserts the environment owner as the worker identity unless `--worker-id` supplies an explicit assertion. Optional `--allowed-cidr` values can narrow the Engagement scope, but cannot expand it or include an excluded destination.

Use synthetic engagements and keys for laboratory evidence. A successful laboratory case proves contract, signature, compatibility, and one-time-consumption behavior for that fixture. It does not prove operating-system process isolation, live target authorization, or network egress enforcement.

## Failure handling

| Rejection | Operator action |
| --- | --- |
| Unknown, expired, or revoked key | Stop. Verify the trust-store version, key identifier, status, and validity window with the verifier owner. |
| Missing or short secret | Restore the approved secret through `secret_env`; never copy it into an input artifact. |
| Operator or engagement mismatch | Regenerate the authorization through the correct authorized operator channel. Do not edit the receipt. |
| Plan, target, operation, argument, or worker mismatch | Review the changed plan and issue a new authorization for the exact approved snapshot and worker. |
| Tool version or platform prerequisite mismatch | Re-measure and reprovision the worker inventory through the trusted owner workflow, or create and approve a plan compatible with the measured worker. |
| Consumed authorization | Treat it as replay. Create a fresh authorization only after confirming a new execution is intended. |
| Legacy untrusted record | Reapprove the current plan through the authenticated channel; legacy checksums cannot be upgraded in place. |

Fail closed on every trust or binding error. Do not bypass verification by changing the plan, receipt, database, or trust-store status.

## Migrate existing approval stores

When an older approval database is opened, existing unsigned or digest-only rows are marked `legacy-untrusted`. They are returned as separate read-only audit records with their previous status retained in `historical_status`; they cannot authorize execution. Migration preserves history but does not create trust.

For an execution that still needs approval:

1. Validate the current Engagement and Action Plan.
2. Configure an active trusted key and its environment-provided secret.
3. Issue a new authenticated authorization for the full snapshot and expected worker.
4. Keep the legacy row only as historical evidence according to the engagement retention policy.

Do not copy a legacy digest into a new envelope or mark a migrated row approved manually.

## Rotate a key

Use an overlap period so in-flight approvals can finish without a verification gap:

1. Provision a new secret in a new environment variable and add its key entry with a future or current activation time.
2. Distribute the updated trust store to verifiers while the old key remains active.
3. Switch the signer to the new key and issue all new authorizations with it.
4. Drain or replace outstanding authorizations created with the old key.
5. Mark the old key `revoked`, deploy that trust-store state, then remove the old environment secret.

Revocation invalidates every unconsumed authorization signed by that key. If immediate revocation is required after suspected disclosure, accept that outstanding receipts will fail and must be reviewed and reissued.

## Remaining execution boundaries

Authenticated authorization proves that a holder of the trusted shared key approved the immutable plan for the expected worker and records whether that one-time authority was consumed. The [worker supervisor](WORKER_SUPERVISOR.md) and [SSH relay](REMOTE_WORKER_SSH_TRANSPORT.md) add a Linux process and transport boundary when correctly provisioned. For an explicitly egress-enabled, signed operation, the worker derives the exact HTTPS endpoint, authenticated service identity, and request targets from the plan and passes a per-operation Unix-socket broker into the Linux network sandbox. The bounded mediator checks live DNS, destination, redirect, TLS peer identity, and resource target while the sandbox denies direct IPv4 and IPv6 access. A policy-free operation receives no broker capability. Repository tests establish the software boundary; operators must validate certificate provisioning, network namespace support, and a real end-to-end request on the intended host before claiming deployment readiness.
