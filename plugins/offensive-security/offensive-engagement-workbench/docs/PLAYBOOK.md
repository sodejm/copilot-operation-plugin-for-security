# Offensive Engagement Workbench playback

## Purpose and safety boundary

This playback demonstrates the planning boundary of the COPS Offensive
Engagement Workbench with a checked-in synthetic engagement. It validates scope,
compiles one draft action plan, proposes an approval-pending specialist handoff,
and crosses a local subprocess boundary without performing the planned security
operation. It makes no network request, calls no model, uses no credential, and
does not authorize live activity.

The child process is launched with the current Python interpreter using `-I -c`.
It reads a small JSON request from standard input and emits one JSON observation
to standard output. The parent validates the complete observation and hashes the
raw stdout and stderr bytes before writing the final success marker. Explicit
semantic checks remain active when Python optimization disables `assert`.

## Prerequisites

- A trusted COPS repository checkout.
- Python 3.11 or newer.
- A writable private output directory for evidence artifacts.
- No network access, service credentials, external model, or assessment worker.

The playback imports the shared COPS runtime, resolves its scenario through the
shared catalog, and routes its proposed handoff through the canonical
`agents/registry.json`. An isolated portable host must provide those declared
framework inputs alongside the exported package. The runner does not search for
or fall back to another source checkout.

Run commands from the repository root. The public catalog command is:

```bash
python3 -m cops demo offensive-engagement-workbench
```

It selects `build/playbacks/offensive-engagement-workbench` as the output
directory. To choose a disposable private directory explicitly:

```bash
COPS_ENGAGEMENT_RUN=$(mktemp -d)
python3 plugins/offensive-security/offensive-engagement-workbench/scripts/demo.py \
  --tool-version python3=3.11.9 \
  --output-dir "$COPS_ENGAGEMENT_RUN"
```

The version value is fixture metadata supplied to the planner; it is not a
measurement of the interpreter running the command.

## Expected result and interpretation

The command prints one machine-readable JSON object:

```json
{
  "engagement_id": "eng-synthetic-e03",
  "mode": "planning",
  "network_requests": 0,
  "operations_count": 1,
  "status": "passed",
  "target": "10.100.0.10"
}
```

Treat the run as passed only when the command exits zero, stdout has exactly
these semantic values, and `playback-result.json` contains the same object.
`operations_count` describes a compiled draft operation. It does not mean that
an assessment operation ran. The handoff must remain `proposed` with
`approval_status` set to `pending`.

## Playback structure and data flow

1. Read the synthetic `engagement.json` fixture and validate its planning scope.
2. Compile exactly one draft action plan for `10.100.0.10`, with egress disabled.
3. Route a specialist and create a proposed, approval-pending handoff through
   the repository handoff API.
4. Atomically write the validated engagement, action plan, and handoff.
5. Dispatch only the engagement ID, mode, target, and operation descriptions to
   the local inert child process.
6. Require exit code zero, empty stderr, valid JSON, and an exact semantic match
   showing zero network requests and one observed operation description.
7. Hash raw child stdout and stderr, then atomically write the observation and
   execution evidence.
8. Write `playback-result.json` last as the completion marker.

```text
synthetic fixture -> intake validator -> draft action plan -> proposed handoff
                                             |
                                             v
                                  local inert subprocess
                                             |
                                             v
                         semantic checks + byte hashes -> result
```

Writing the result last makes completion unambiguous. Atomic replacement avoids
partially written JSON files. The injectable dispatcher keeps the failure path
testable: tests substitute a well-formed observation that claims a network
request and verify that the run fails closed.

## Artifact schema

| Artifact | Purpose | Key fields | Producer | Consumer | Definition | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `engagement.json` | Preserve validated planning scope. | `engagement_id`, `mode`, `operator`, `rules_of_engagement` | Intake validator | Planner and operator | Normalized `cops.engagement/v1` contract derived from the fixture. | Mode must be `planning`; intake validation must pass. | `"engagement_id": "eng-synthetic-e03"` |
| `action-plan.json` | Record the single proposed assessment operation and its limits. | `status`, `target`, `operations`, `limits`, `plan_digest` | Action-plan builder | Handoff router and operator | Draft `cops.action-plan/v1` contract for the synthetic target. | Exactly one operation; target `10.100.0.10`; status `draft`; egress false. | `"status": "draft"` |
| `handoff.json` | Record who would review the proposal without granting execution. | `handoff_id`, `specialist_id`, `status`, `approval_status`, plan binding | Specialist handoff router | Specialist and operator | `cops.specialist-handoff/v1` proposal bound to the plan and engagement. | Status `proposed`; approval status `pending`; registered capability route. | `"approval_status": "pending"` |
| `inert-observation.json` | Capture what the local child observed in the dispatch request. | `dispatcher`, `engagement_id`, `mode`, `target`, `operation_ids`, `operations_count`, `network_requests` | Isolated local child | Parent playback validator | Compact observation of descriptions received by the child, not operation execution evidence. | Exact object match; zero network requests; one operation ID. | `"dispatcher": "local-inert"` |
| `execution-evidence.json` | Bind the child process result to its raw output bytes without retaining command-line data. | `dispatcher`, allowlisted `flags`, `returncode`, byte counts, stdout/stderr SHA-256 | Parent playback runner | Operator and package tests | Stable dispatcher identity, safe isolation flags, and `sha256:` digests of raw stdout and stderr. Executable paths, inline program text, and arbitrary arguments are omitted. | The runner requires its built-in dispatcher, then verifies the current Python executable, `-I` immediately after it, the approved inline child, and the exact argument count before recording `python-isolated`; return code is zero, stderr is empty, and hashes recompute from raw captured bytes. | `"dispatcher": "python-isolated"` |
| `playback-result.json` | Mark successful completion after every earlier check and write. | `status`, `mode`, `engagement_id`, `target`, `network_requests`, `operations_count` | Parent playback runner | Catalog demo and operator | Stable six-field acceptance summary. | Must equal the documented result exactly and be written last. | `"status": "passed"` |

## Failures and insufficient evidence

A nonzero exit, `playback failed:` message, absent result file, changed result
field, child stderr, unapproved subprocess argument shape, or malformed or
semantically different observation is a failed playback. The runner removes any
stale `playback-result.json` before work begins, so an earlier success cannot
certify a later failed attempt. Earlier artifacts may remain after a failure;
treat them as diagnostic fragments, not a completed run.

This playback supplies no evidence that the synthetic IP is reachable, a live
target is authorized, an exploit works, a worker is ready, network isolation is
enforced by the host, or a model produced a sound security judgment. The
stdout/stderr hashes bind locally captured bytes only; they are not signatures or
third-party attestations.

## Reruns and cleanup

Rerunning with the same output directory atomically replaces the six known
artifacts and preserves unrelated operator files. Handoff timestamps may change;
compare documented semantic fields and contract bindings instead of requiring
byte-identical artifacts. If a run fails, correct the input or local filesystem
problem and rerun the same command. Success requires a newly written final result.

Remove disposable evidence when it is no longer needed:

```bash
rm -rf "$COPS_ENGAGEMENT_RUN"
```

Keep private engagement data outside shared build directories. For broader
package qualification, including independent scope comparison and host-specific
checks, continue with [VERIFICATION.md](VERIFICATION.md).

<!-- BEGIN COPS GENERATED OFFLINE ASSESSMENT LINKS -->
## Generated offline assessment

- [Machine-readable playbook](../playbooks/offline-assessment.json)
- [Runnable offline walkthrough](../walkthroughs/offline-assessment.md)
<!-- END COPS GENERATED OFFLINE ASSESSMENT LINKS -->
