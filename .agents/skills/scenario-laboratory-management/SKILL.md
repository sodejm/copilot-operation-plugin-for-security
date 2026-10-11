---
name: scenario-laboratory-management
description: Manage scenario laboratory contracts with measured isolation, canary, reset, scope, and case outcome gates.
---

# Scenario Laboratory Management

Manage operator-controlled container and VM laboratories for security scenarios. The harness validates tested platforms and tools, verifies independently signed operator observations, and dispatches authorized cases to an SSH endpoint pinned in an owner-provisioned inventory. The operator supplies the actual runtime isolation, measurement, reset, and worker services; the contract alone does not establish those controls.

## Core Responsibilities

1. **Verify the environment**: Check the platform and tool matrix. Require an operator-owned `observation_provider(environment, nonce)` that measures the runtime boundary, egress restriction, canary digest, and clean baseline. The `LaboratoryObservation` must be signed by an independent operator adapter whose public Ed25519 key is pinned in a verified `LaboratoryObservationTrustStore`; it must match the fresh challenge. Keep the private signer outside the controller and SSH dispatch inventory.
2. **Verify a reset**: Call `begin_reset(environment)` to invalidate the earlier verification and obtain a single-use nonce. Have the operator's worker perform the configured reset. Pass the adapter's signed `LaboratoryResetReceipt` to `reproducible_reset`, which also requires a fresh signed post-reset observation. The harness does not run the reset command.
3. **Run and classify a case**: Supply a signed authorization, engagement, verified worker capability and SSH endpoint inventories, an explicit `ScopeGuard`, and an owner-only `LaboratoryCaseJournal` used by one controller process. `execute_case` records intent before SSH dispatch and returns a `RemoteAuthorizedRun`. Call `case_observation_challenge` to obtain a fresh nonce and get a signed `LaboratoryCaseObservation` from the independent adapter after completion. Call `classify_case` with that observation and the bound result. Classification checks the worker's `RunResult.cleanup_status`; it retains complete signed observation receipts in result details and does not issue a separate laboratory cleanup receipt. Call `expire_pending_cases` after the two-minute deadline; challenge, classification, and `recorded_cases` also check it. Controller restart, reset, or reverification fails cases lacking valid observations.

## CLI Usage

```bash
python3 -m cops lab matrix
python3 -m cops lab register path/to/env.json
```

Registration records a contract; it does not verify a running environment. The bundled `lab verify`, `lab reset`, and `lab run` commands fail closed until an operator integration supplies the live observation, worker reset, and case result flows through the Python API.

## Python API Sequence

```python
from cops.laboratory import LaboratoryCaseJournal, LaboratoryHarness, LaboratoryObservationTrustStore

# The adapter signs measured observations with a private key unavailable to this process.
observation_trust_store = LaboratoryObservationTrustStore.from_file(observation_trust_path)
harness = LaboratoryHarness(
    observation_provider=operator_observe,
    observation_trust_store=observation_trust_store,
    case_journal=LaboratoryCaseJournal(case_journal_path),
)
environment = harness.verify_environment(environment, endpoint_inventory=endpoint_inventory)

nonce = harness.begin_reset(environment)
reset_receipt = operator_reset(environment, nonce)  # independently signed receipt
environment = harness.reproducible_reset(
    environment, reset_receipt=reset_receipt, endpoint_inventory=endpoint_inventory
)

# trust_store, engagement, and worker_inventory are independently provisioned.
authorized_run = harness.execute_case(
    environment, plan, authorization, "positive",
    trust_store=trust_store,
    engagement=engagement,
    worker_inventory=worker_inventory,
    endpoint_inventory=endpoint_inventory,
    scope_guard=scope_guard,
)
case_nonce = harness.case_observation_challenge(authorized_run)
case_observation = operator_observe_case(environment, plan, authorized_run, case_nonce)
result = harness.classify_case(
    environment, plan, authorized_run, authorization.authorization_id, "positive",
    case_observation=case_observation,
    endpoint_inventory=endpoint_inventory,
)
```

Load `WorkerCapabilityInventory`, `SSHRemoteEndpointInventory`, and `LaboratoryObservationTrustStore` with their protected `from_file` constructors. The observation store contains public keys; the independent adapter retains private signing keys. The operator remains responsible for whether the adapter measures the actual runtime correctly. Offline synthetic receipts exercise the contract only; they do not prove live isolation or egress enforcement.
