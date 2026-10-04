---
name: engagement-contract-validation
description: Validate versioned engagement, scenario, action plan, run result, and finding contracts and their lifecycle transitions.
---

# Engagement contract validation

Validate and manage the integrity and lifecycle state transitions of COPS operational contracts:

- **Engagement** (`cops.engagement/v1`): Authorized assessment scope, rules of engagement, authorized time window, and operator identity.
- **Scenario** (`cops.scenario/v1`): Security assessment attack path mapped to MITRE ATT&CK techniques, environment requirements, and safety profiles.
- **ActionPlan** (`cops.action-plan/v1`): Immutable operation sequence bound to scenario and engagement with cryptographically verifiable `plan_digest`.
- **RunResult** (`cops.run-result/v1`): Execution outcome preserving truthfulness; non-success states (`partial`, `cancelled`, `failed`, `uncertain`, `not_assessed`) require explicit reasons and are never treated as false success.
- **Finding** (`cops.finding/v1`): Normalized security findings requiring linked evidence references for verified status.

## CLI Usage

### Validate a Contract File

To validate any operational contract against its schema and domain invariants:

```bash
python3 -m cops contract validate <path-to-contract.json>
```

You can optionally specify the expected type:

```bash
python3 -m cops contract validate <path-to-contract.json> --type engagement
```

Supported types: `engagement`, `scenario`, `action_plan`, `run_result`, `finding`.

### Validate a Lifecycle State Transition

To verify whether a lifecycle state transition is legally permitted:

```bash
python3 -m cops contract transition <current_state> <target_state> --type <engagement|action_plan>
```

#### Engagement Transitions
- Allowed:
  - `planned` -> `active`, `cancelled`
  - `active` -> `completed`, `cancelled`, `aborted`
- Terminal states: `completed`, `cancelled`, `aborted` (no further transitions permitted)

#### Action Plan Transitions
- Allowed:
  - `draft` -> `pending_approval`, `cancelled`
  - `pending_approval` -> `approved`, `rejected`, `cancelled`
  - `approved` -> `executing`, `cancelled`
  - `executing` -> `fulfilled`, `cancelled`
- Terminal states: `fulfilled`, `rejected`, `cancelled`

## Python API

```python
from cops.contracts import (
    Engagement,
    Scenario,
    ActionPlan,
    RunResult,
    Finding,
    validate_contract,
    validate_transition,
    evaluate_run_result,
)

# Validate a raw dictionary
validated_doc = validate_contract(data)

# Load into typed model and transition
engagement = Engagement.from_dict(data)
engagement.transition_to("active")

# Check execution outcome
result = RunResult.from_dict(result_data)
if not result.is_successful():
    print(f"Action did not succeed: {result.status} - {result.status_details['reason']}")
```

## Error Codes

- `malformed_identifier`: Identifier does not match required syntax prefix (`eng-`, `scen-`, `plan-`, `res-`, `find-`).
- `unsupported_version`: `schema_version` is missing or unrecognized.
- `illegal_transition`: Attempted state transition is disallowed by the lifecycle state machine.
- `integrity_mismatch`: Digest or cryptographic hash check failed (e.g. tampered action plan).
- `credential_leak_detected`: Plaintext secret or token detected in credential references.
- `invalid_timestamp`: Timestamp sequence violation (e.g. end time before start time).
- `missing_reason`: Non-success run result omitted mandatory explanation.
- `missing_evidence_reference`: Finding marked as `verified` without attached evidence records.
