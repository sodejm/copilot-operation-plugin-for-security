# Versioned workflows and purple-team handoffs

COPS workflows are strict, typed directed acyclic graphs. They coordinate
existing workers through the existing `ActionPlan` and approval authority; the
workflow layer does not create approvals or expand targets. The Python contract
is exposed from `cops.workflows`, and its machine-readable schema is
`catalog/schemas/workflow-definition.schema.json`.

## Workflow definition

Parse untrusted JSON with `WorkflowDefinition.from_dict(document)`. The parser
rejects unknown fields, invalid JSON types, duplicate or missing dependencies,
cycles, references to missing outputs, incompatible binding types, unresolved
workflow outputs, and definitions that exceed their declared stage or attempt
budgets. Action target, specialist, tool, tool version, and action are literal
values; interpolation such as `${workflow.input.target}` is rejected. This
prevents an input or upstream result from widening an approved target.

This single-stage document is executable:

```json
{
  "schema_version": "cops.workflow-definition/v1",
  "workflow_id": "ioc-flow",
  "engagement_id": "eng-workflows",
  "scenario_id": "COPS-E99.01-S01",
  "inputs": {
    "query": {"type": "string", "required": true}
  },
  "outputs": {
    "count": {"type": "integer", "source": "stage.probe.output.count"}
  },
  "budget": {
    "max_stages": 4,
    "max_total_attempts": 2,
    "max_output_bytes": 4096,
    "max_evidence_refs": 4
  },
  "stages": [
    {
      "stage_id": "probe",
      "depends_on": [],
      "inputs": {
        "query": {"type": "string", "source": "workflow.input.query"}
      },
      "outputs": {
        "count": {"type": "integer"}
      },
      "retry": {"max_attempts": 2},
      "action": {
        "target": "lab://fixture",
        "specialist_id": "lab-worker",
        "tool": "fixture-probe",
        "tool_version": "1.0.0",
        "action": "probe",
        "timeout_seconds": 30,
        "limits": {
          "max_duration_seconds": 30,
          "max_output_bytes": 4096,
          "egress_allowed": false
        },
        "cleanup": {"strategy": "none", "resources": []}
      }
    }
  ]
}
```

Bindings may contain a literal `value`, reference `workflow.input.<name>`, or
reference `stage.<stage-id>.output.<name>`. A stage must declare every upstream
stage it references in `depends_on`. Conditions support `exists`, `eq`, and
`not_eq` against those same sources. Conditions only decide whether an already
declared stage runs; they cannot synthesize a target or action.

## Compiling and running

`compile_action_plan(definition, run_id, stage_id, resolved_inputs, created_at,
attempt=1)` creates the exact `ActionPlan` for an executable stage. The plan
digest binds the workflow definition, run, stage, attempt, resolved inputs,
target, action, limits, and execution metadata. A changed target, action,
input, or retry attempt therefore needs a separately matching authorization.

Construct `WorkflowRunner(state_dir, approval_control, worker_identity,
executor)`, then call:

```python
result = runner.run(
    definition,
    "run-123",
    {"query": "example"},
    {
        "probe:1": "authorization-for-first-plan",
        "probe:2": "authorization-for-retry-plan"
    },
    cancellation_requested=is_cancelled,
)
```

The first attempt may use either `stage-id` or `stage-id:1` as its authorization
map key. Later attempts require `stage-id:<attempt>`. The runtime consumes each
authorization through `ApprovalControl`, validates the returned receipt, and
passes that receipt to `WorkflowExecutor.execute`. It never derives an approval
from an earlier attempt. Retries use a stable stage idempotency key so a worker
can suppress duplicate side effects, while the retry plan and authorization are
fresh.

Stage results use `StageExecutionResult(status, outputs, evidence_refs, reason)`.
The runtime type-checks them, enforces output and evidence budgets, and persists
digest-protected state and result artifacts. Resume verifies the definition,
inputs, state digest, and every referenced artifact before doing work. Result
files use exclusive creation to prevent duplicate writes. A completed stage is
not executed again. Run one runner at a time for a given run ID and state
directory; cross-process scheduling and locking belong to the caller.

Cancellation is checked before each stage and attempt. A failed or interrupted
stage with a declared cleanup operation completes cleanup before cancellation or
another attempt. If a process stops after authorization consumption, resume
marks that attempt interrupted and requires a fresh authorization for the next
bounded attempt. Terminal stage failure returns `partial_failure`; dependent
stages do not run.

## Purple-team handoff

`emit_purple_team_handoff(source_result, expected_telemetry, correlation_ids,
window, evidence_refs)` accepts a source with `kind` equal to `finding` or
`simulation` and produces `cops.purple-team-handoff/v1`. The strict schema is
`catalog/schemas/purple-team-handoff.schema.json`. The handoff names the source
reference, expected telemetry fields and values, correlation IDs, an inclusive
time window, evidence references, and a detection result.

Evaluate it with `evaluate_purple_team_handoff(handoff, telemetry, alerts,
attack_fixture=(), benign_fixture=())`. The result classifications are:

| Status | Evidence |
| --- | --- |
| `instrumentation_gap` | Logs are unavailable, or no expected correlated telemetry was captured in the time window. |
| `detection_gap` | Expected correlated telemetry exists, but no actual correlated alert was observed. |
| `verified_detection` | Actual expected telemetry and an event with `alert: true` share a requested correlation ID and fall in the time window. |
| `indeterminate` | Source evidence or alert evidence is missing. |

A detection gap includes Sigma and KQL proposals. The evaluator executes each
generated proposal against the supplied attack and benign fixtures and reports
`attack_matches` and `benign_matches`. `rule_execution` records each proposal's
digest, supported subset version, counts, and whether the two engines agree.
It raises `rule_execution_mismatch` instead of choosing or inventing a count if
the engines disagree. `execute_simple_rule(rule, events)` remains public for
correlation-aware fixture playback; its correlation filter is separate from
the proposal predicates.

The executable Sigma subset is `cops.sigma-selection-equality/v1`: a document
with exactly `title` and `detection`, where `detection.condition` is the literal
`selection` and `detection.selection` contains one to 64 field-path/string-value
pairs combined with AND. The executable KQL subset is
`cops.kql-conjunctive-string-equality/v1`: one to 64 expressions in the exact
form `field.path == "string"`, joined by lowercase ` and `. KQL string values
support only `\"` and `\\` escapes and contain no raw control characters.
Field paths use identifier components separated by dots. Call
`execute_sigma_proposal(proposal, events)` and
`execute_kql_proposal(proposal, events)` from `cops.workflows.purple` for direct
fixture execution. OR, negation, functions, wildcards, numeric or Boolean
literals, alternate conditions, duplicate KQL fields, extra Sigma keys, and
malformed input are rejected explicitly with `sigma_rule_unsupported` or
`kql_rule_unsupported`. The evaluator never treats an unsupported rule as zero
matches or successful execution. Generated proposals remain review artifacts;
they do not install detection content or start network activity.

The service laboratory can feed this evaluator from
`ServiceLaboratory.run_offline_playback()` or
`ServiceLaboratory.run_process_acceptance(profile)`. A process run proves
functional behavior and reports isolation as unverified unless the kernel
boundary checks succeed. Preserve the report from `to_dict()`
(`cops.service-laboratory-report/v1`) as an evidence reference.

The required `make check-laboratory` gate also checks restoration and actual
activity. Its Docker runtime inspects the container before starting it and
verifies the Linux interfaces, routes, source snapshot, and bounded IPv4/IPv6
egress rejection from inside it. See [service laboratories](SERVICE_LABORATORY.md).
The disposable workflow adapter exercises signed plans and one-use authorization
in process. Production dispatch remains the separate
`LaboratoryHarness.execute_case(ActionPlan, authorization, ...)` worker boundary;
these functional cases do not validate its distinct-UID or native-platform
isolation requirements.
