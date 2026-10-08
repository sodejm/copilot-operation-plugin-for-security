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
    "nmap": "7.95"
  },
  "platform_capabilities": [
    "raw-sockets"
  ]
}
```

`measured_at` must be canonical UTC and cannot be in the future. The loader accepts only a non-symlink regular file owned by the current user with no group or other permission bits; mode `0600` is the normal choice. Keep the measurement workflow and artifact distribution inside the worker owner's trusted boundary.

COPS loads and compares this owner-provisioned attestation. It does not discover installed executables at runtime or prove that the recorded measurement is accurate. Re-measure and replace the artifact through the trusted provisioning workflow whenever the worker's tools or platform capabilities change.

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

Provide the plan, authorization, verifier trust store, engagement, and independently provisioned worker inventory:

```bash
python3 -m cops worker execute action-plan.json \
  --authorization execution-authorization.json \
  --authorization-trust-store authorization-trust-store.json \
  --engagement engagement.json \
  --worker-inventory worker-capability-inventory.json \
  --worker-id worker-lab-01 \
  --db approvals.sqlite3 \
  --json
```

`--worker-id` is optional; when omitted, the command uses the inventory identity. The worker rejects inventory identity mismatches, missing tools, version mismatches, missing platform capabilities, unsupported batch semantics, and operation counts above the signed batch maximum before execution.

Library callers must pass the `WorkerCapabilityInventory` loaded by
`WorkerCapabilityInventory.from_file` directly to `IsolatedWorker`; caller-built
inventories and mutable `WorkerConfig` values are not accepted at the worker
boundary.

The approval store consumes the authorization in a SQLite transaction immediately before dispatch. A second attempt with the same authorization fails as replay. Keep the approval database on durable local storage and protect it with the same access controls as other execution records.

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

Authenticated authorization proves that a holder of the trusted shared key approved the immutable plan for the expected worker and records whether that one-time authority was consumed. It does not by itself create an operating-system or process transport boundary, which is tracked in issue #185. It also does not mediate live network egress, DNS resolution, redirects, or cloud metadata access, which is tracked in issue #186. Deployments must supply those controls independently before claiming isolated or destination-enforced live execution.
