# Incident Response Sandbox operator playback

## Purpose and boundary

This playback exercises the package's incident-plan state machine against private
copies of a synthetic JSON fixture. It generates expiry values from the current
UTC clock, proves a ready dry run does not mutate state, executes one isolation,
rejects replay and expiry, simulates a partial failure, and verifies rollback.

The package has no production adapter. The fixture's provider request ID and
post-action verification are deterministic local evidence shapes, not provider
receipts. The approver field is a self-recorded assertion and grants no authority.

## Prerequisites and command

Run from the COPS repository root with Python 3.11 or newer:

```sh
P=plugins/incident-response/incident-response-sandbox
python3 "$P/scripts/validate-package.py"
python3 -m cops demo incident-response-sandbox
COPS_IR_PLAYBACK=$(mktemp -d "${TMPDIR:-/tmp}/cops-ir-playback.XXXXXX")
chmod 700 "$COPS_IR_PLAYBACK"
python3 "$P/scripts/run_demo.py" > "$COPS_IR_PLAYBACK/result.json"
python3 -m json.tool "$COPS_IR_PLAYBACK/result.json"
```

The runner copies the fixture into a mode-`0700` temporary directory, sets the
fixture to mode `0600`, checks every outcome, prints one JSON object, and removes
the directory. The command stores that result in a separate private directory.

## Reading the result

| Field | Expected meaning |
| --- | --- |
| `schema` | `cops.incident-response-playback/v1`, the playback envelope contract. |
| `execution_boundary.network_calls` | `0`; only local fixture state was used. |
| `execution_boundary.live_containment_validated` | `false`; no provider was contacted. |
| `execution_boundary.temporary_artifacts_removed` | `true` after runner cleanup. |
| `primary.dry_run_decision` | `ready`; scope, state, permission, expiry, and throttle checks passed. |
| `primary.dry_run_state_unchanged` | `true`; the ready check left the source fixture state unchanged. |
| `primary.execute_status` | `applied`; the local target changed from active to isolated. |
| `primary.post_action_verification.result` | `succeeded` for the included fixture. |
| `replay_rejection.rejected` | `true`; a duplicate execution or stale receipt was rejected. |
| `expiry_rejection.rejected` | `true`; a plan evaluated after its generated expiry was rejected. |
| `rollback.execute_status` | `partial-rolled-back`; the simulated failure restored the target. |
| `rollback.verification_state` | `active`, confirming successful local rollback. |

## Design and data flow

1. `build_plan` binds action, tenant, target, expiry, nonce, and approver assertion
   into a typed plan and content hash.
2. `dry_run` checks the plan against the fixture without mutation and binds a
   receipt to plan hash, fixture revision, target state, and time.
3. `execute` rechecks both artifacts, writes a deterministic request ID, mutates
   the fixture, verifies the new state, and appends an execution ledger record.
4. A second execution is rejected because its plan or receipt is consumed or
   stale. A separate validation checks the plan after its generated expiry.
5. A fresh fixture with `failure_mode: partial` enters isolation and then returns
   to active state through rollback.
6. The runner checks semantic outcomes and deletes all temporary state.

## Contracts and validation

`Plan` is a Python `TypedDict`; the other records are runtime dictionaries. The
package has no standalone JSON Schema for these files. Do not invent an external
schema validator from this table.

| Contract | Purpose | Key fields | Producer | Consumer | Definition | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Plan | Bind one requested fixture action to scope and time. | `schema`, action, tenant, target, states, `expires_at`, `nonce`, approver assertion, `plan_hash` | `build_plan` or `ir.py plan` | `dry_run`, `execute` | `Plan` `TypedDict` in `incident_response/core.py` | `validate_plan` checks schema, action, time, identifiers, and hash. | `action: isolate-host`. |
| Fixture | Represent synthetic provider state and history. | `schema`, tenant, permissions, targets, `revision`, `executions`, optional failure controls | Package fixture or operator copy | `dry_run`, `execute` | Runtime dictionary contract in `incident_response/core.py` | Core state checks plus CLI file-mode and JSON bounds. | `targets.host-1.state: active`. |
| Dry-run receipt | Bind readiness to an exact plan and fixture state. | `schema`, `decision`, `plan_hash`, `fixture_revision`, `target_state_hash` | `dry_run` | `execute` | Runtime dictionary contract returned by `dry_run` | Execution recomputes the bindings; altered, expired, or stale receipts fail closed. | `decision: ready`. |
| Execution result | Record local action, rollback, and verification outcome. | `schema`, `plan_hash`, `outcome`, `fixture_revision`, approval provenance, request ID, post-action verification | `execute` | Operator and fixture ledger | Runtime dictionary contract returned by `execute` | Package tests cover replay, partial failure, rollback failure, and unavailable verification. | `outcome: applied`. |
| Playback envelope | Summarize all bounded scenarios. | `schema`, `execution_boundary`, `primary`, `replay_rejection`, `expiry_rejection`, `rollback` | `scripts/run_demo.py` | Operator or regression test | Runner-owned JSON contract; no standalone JSON Schema exists. | Explicit runner checks and `tests/test_incident_response_playback.py`, including optimized Python. | `network_calls: 0`. |

## Artifact-preserving manual flow

Use the manual command block in [VERIFICATION.md](VERIFICATION.md) when you need to
inspect the plan, receipt, and fixture between steps. Always generate the expiry
from the current clock, use a new nonce, and copy the package fixture into a new
mode-`0700` directory. Compare the plan hash, receipt binding, fixture revision,
target state, execution ledger, request ID, and verification reference.

## Reruns, failures, and cleanup

Every rerun needs a fresh fixture copy, future expiry, nonce, and receipt. Times,
plan hashes, verification references, and request IDs can differ because they bind
to the new plan and fixture revision. Compare statuses and state transitions rather
than expecting byte-identical output.

Replay, expired plans, changed plans, stale receipts, scope mismatches, missing
permission, and throttling must fail closed. `partial-rolled-back` means the
synthetic rollback restored state. `partial-rollback-failed` leaves unresolved
fixture state and requires operator review; do not report it as contained.
`post_action_verification.result: unavailable` is unverified, never successful.

The playback removes its temporary state automatically. For a manual run, retain
artifacts only under the applicable incident-record policy, then securely remove
the run directory. Never remove the package's source fixture during cleanup.

## Troubleshooting and limitations

An immediate expiry error usually means a copied static plan or an expiry that is
not later than the current UTC time. Generate it immediately before the run. A
fixture permission error requires a private copied file with mode `0600`. A replay
on the same fixture is expected to fail; copy a fresh fixture for a new exercise.

This playback does not validate provider credentials, APIs, production rollback,
concurrent writers, immutable audit storage, identity attestation, host adapter
installation, or emergency authorization. It must not be used as evidence that a
live containment action occurred.
