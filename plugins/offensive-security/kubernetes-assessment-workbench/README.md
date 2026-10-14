# COPS Kubernetes Assessment Workbench

Reconcile an approved Kubernetes context and namespace scope against a sanitized
local observation before deciding what evidence to collect next. This experimental
package checks whether the two records agree and makes missing access explicit.
It reads no kubeconfig, calls no cluster API, and does not authorize execution.

## Start here

Use Python 3.11 or newer. Run these commands from the repository root:

```bash
python3 -m cops info kubernetes-assessment-workbench
python3 -m cops demo kubernetes-assessment-workbench
python3 -m cops check kubernetes-assessment-workbench
```

The demo runs matching, limited-evidence, and rejected context-switch cases through
the public importer. It asserts each result and repeats the matching case. Follow
the [practitioner playback](docs/PLAYBOOK.md) to inspect an individual report, or
use the [verification playbook](docs/VERIFICATION.md) to record qualification evidence.

## Why context reconciliation comes first

A context name alone cannot establish which cluster or identity supplied evidence.
The importer compares the selected name, cluster, and user with the observation's
context inventory. An optional Namespace UID provides a second identity anchor.
`matched_sanitized_export` means that two local assertions agree on that object;
it does not prove a universal cluster identity or fresh live access.

The report keeps identity, namespace access, surface access, and cluster facts
separate. A denied namespace cannot become accessible because the API server is
reachable. Missing observations stay `unknown`. Managed control-plane restrictions
remain limitations, even when the selected namespace is accessible. Every report
sets `live_execution_ready` to `false` and `network_requests` to `0`.

## Data contracts

The [complete synthetic input](fixtures/synthetic/context.json) is a runnable
example. The importer enforces the versioned
[context contract](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/specs/kubernetes-assessment-context.spec.md).

| Record or field | Purpose and producer | Consumer and validation |
| --- | --- | --- |
| Input `schema_version`, `mode` | Operator identifies contract `1.0` and `offline` processing | Importer rejects unsupported versions and modes |
| `plan.approval_reference` | Operator records the applicable approval identifier | Retained as an assertion; no signature or authority is verified |
| `plan.context` | Exact `name`, `cluster`, and `user` to reconcile | Must match the observation without ambiguous duplicate contexts |
| `plan.namespaces`, `plan.surfaces` | Explicit scope; surfaces are `api_server`, `namespaced_resources`, `control_plane`, `nodes`, `network` | Importer rejects wildcard scope and unsupported surfaces |
| `plan.identity_anchor` | Optional Namespace name and UID | Compared with `observation.identity_anchor`; conflict rejects the record, absence remains unresolved |
| `observation.current_context`, `contexts` | Sanitized exported context selection and inventory | Must support the exact selected context |
| `namespace_access`, `surface_access` | Observed access assertions | `accessible`, `denied`, `unknown`; surfaces also accept `unavailable`; omitted evidence becomes unknown |
| `cluster_facts` | Version, distribution, runtime, node OS, network, admission controls, control-plane and node access | Missing facts stay unknown; restricted control-plane or node access becomes a limitation |
| Report `cluster_identity`, `namespaces`, `surfaces` | Importer explains the reconciled evidence | Analyst uses these alongside the original record; no live finding is established |
| Report `blockers`, `limitations` | Importer identifies missing identity, incomplete access, and unavailable surfaces | Analyst determines the next authorized collection step |

Inputs are bounded to 128 KiB, nesting depth 16, and bounded inventories. Duplicate
JSON keys, non-finite numbers, credential fields, and unsupported fields fail
closed. Use opaque identifiers; omit server URLs, credentials, kubeconfig, and
workload data.

## Failure and operational limits

A mismatched context exits with code 2 and a stable error code. A valid but incomplete
record produces a report with blockers; it is not a successful assessment of those
surfaces. Fix the source or obtain the missing evidence, then rerun the importer.
Do not remove blockers by inventing observations.

The package has no cluster collector, node probe, admission-controller integration,
or exploitation capability. Host installation and live integration remain
unverified. Local fixture evidence cannot promote those support states.
