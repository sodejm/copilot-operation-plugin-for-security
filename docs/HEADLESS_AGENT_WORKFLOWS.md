# Headless workbench operations

COPS keeps conversation and peer-agent launch in your harness. Its operation
service handles deterministic supplied-data processing. The CLI and optional
local stdio MCP adapter use the same schemas, allowlisted implementations, and
result contract. The headless entry point is limited to offline defensive work.
Optional private local state supports resumable runs and recorded peer responses.

## Choose the lightest workflow

- **Try a sample:** call `cops.work.request` with only `task`. Artifact references,
  context, and informal peer notes are optional. No engagement, specialist, DAG,
  approval, or persistent session is needed.
- **Use a workbench:** call a named assessment or SOC operation directly. A work
  request is not mandatory setup. Pass inline data, interpret results, and retain
  returned snapshots in your harness.
- **Request human review:** `cops.work.escalate` records a proposal with
  `authority: none`. The harness can present it for review.
- **Retain progress:** opt into the configured `cops.run.*` lifecycle when process
  restart or shared status is useful. This is optional, not setup for every sample.

Classify and redact input before sending it to the harness or tools. Treat
returned exploration notes and peer responses as unverified claims.

For the Detection Quality workflow, open the COPS entry point in Copilot and ask
“Check whether our Sentinel and Splunk detections catch the bundled cases.”
After interruption, say “Resume my review” in the same chat. The Copilot pilot
uses its own fixture checkpoint. [Detection Quality pilot](detection-quality-pilot.md)

## CLI

```bash
python3 -m cops tools list --json
python3 -m cops tools describe cops.work.request --json
python3 -m cops tools validate
python3 -m cops tools invoke --request -
```

Supply one JSON object on stdin to the last command, then close stdin:

```json
{
  "schema_version": "cops.operation-request/v1",
  "request_id": "sample-01",
  "operation_id": "cops.work.request",
  "arguments": {"task": "Inspect this sample; do not execute it"}
}
```

The CLI emits one JSON object on stdout. `needs_input`, `blocked` and `failed`
exit 2. Inspect the status and domain result for any evidence gaps.

Input/output documents are limited to 8 MiB, depth 48, and 100,000 value nodes.
Underlying assessment and SOC limits still apply. Errors contain stable codes,
not rejected values. Request IDs must be opaque aliases, never secrets or PII.

## Pilot operations

- `cops.assess.<capability>` exposes all existing offline artifact assessment
  capability IDs. Arguments are `artifacts` and canonical UTC `as_of`. Supply
  `content` as JSON/text or `content_b64` for bytes; the engines retain their
  existing bounds and evidence contracts.
- `cops.soc.validate`, `.next`, and `.report` accept an inline `case`.
- `cops.soc.handoff` also requires `step_id`; it verifies the bundled Sentinel
  dependency and returns package-relative canonical references. Those references
  are data, not permission to invoke an arbitrary path.
- `cops.soc.import` accepts `case` and `observation`; `.revise` accepts `case` and
  `steps`. Both return a new `case` and snapshot hash. No case file is written.
- `cops.work.note` accepts `request` and free-form `note`; `.escalate` accepts
  `request` and proposed `action`. Neither launches a specialist or worker.

Missing top-level operation inputs produce `needs_input`. Invalid supplied types,
unknown arguments and invalid domain contracts fail. A missing installed SOC
runtime or dependency blocks the call; it is never replaced with a guessed flow.
Tools accept supplied data only. Apparent paths and commands inside evidence
remain inert. The CLI and MCP catalog expose the same offline allowlist.

## Optional durable local runtime

Configure the harness process with `COPS_RUNTIME_CONFIG` pointing to an absolute,
owner-only regular JSON file. On POSIX it must be owned by the current account,
mode `0600`, and accessible without symlink components. For example, a local
configuration (never commit real installation paths or evidence) can contain:

```json
{
  "schema_version": "cops.operation-runtime/v1",
  "state_directory": "/approved/private/cops-runs",
  "installed_root": "/approved/cops-install"
}
```

The state directory is created as `0700`, or must already have exactly that mode
and the current owner. The SQLite file is `0600`; redirection and hard links fail
closed. Persistent state currently requires POSIX. Pure tools remain available
without runtime configuration and on other supported Python platforms. Discovery
reads static declarations without loading configuration or creating a database. Runtime paths are
installation configuration, not accepted tool arguments.

Use `cops.run.create` with `request` containing a complete existing pure operation
request and optional `idempotency_key`. It returns a queued record without running
the operation. `cops.run.resume` takes its `run_id`. `status`, `cancel` and `recover`
also take that ID. Recursive run/delegation calls cannot be submitted as pure work.
An idempotency key binds semantic inputs, implementation/declaration digests and
execution mode; a different transport `request_id` does not create another run.
Changed semantic input conflicts. Terminal results are returned without reexecution.

SQLite admission fences competing processes with a private attempt token and a
120-second lease. Execution happens outside the database transaction. An expired
attempt can be recovered and retried. If cancellation was requested, the next
recovery marks the expired attempt cancelled and suppresses its result. A
still-active lease reports `run_busy`. Lease expiry cannot establish that a
process stopped. Queued cancellation is terminal. Running cancellation records
intent and suppresses results that arrive after the request.

The ledger retains classified inputs and results. Protect and manage retention.
It admits at most 64 run and delegation records, caps run input at 2 MiB, stored
operation results at 4 MiB and each record at 8 MiB, and sets a 1 GiB SQLite page
cap. It reserves capacity before execution and retains history. Older
worker-backed records stay in place for separate operator handling. The headless
runtime rejects those records and configurations with worker fields.

## Optional bound peer responses

Use ordinary `cops.work.request` and `.note` for informal handoffs. If a response
needs durable correlation, `cops.delegate.prepare` accepts `task`, optional
`scope_ref`, and optionally a pair of `specialist_id` and `skill_id`. A selected
`operation_id` must belong to that installed skill's plugin. The resolver prefers
installed product skills over contributor fallbacks and binds the skill bytes.
No specialist or workflow DAG is required for a task-only delegation.

The returned `delegation_id` and `binding_digest` identify the task and scope.
`cops.delegate.accept` takes the ID and a `peer_response` with the same digest and
scope alias, optional `notes`, and optional schema-valid `operation_result` matching
the selected operation. Changed implementations, substituted scopes/operations and
duplicate responses are rejected. Acceptance records `untrusted_peer_claims_only`:
it does not authenticate a peer identity, validate a finding, or prove tool execution.
The harness still owns peer-agent launch and conversation.

## Local MCP

Install the optional dependency in your project virtual environment:

```bash
.venv/bin/python -m pip install -r requirements-mcp.txt
.venv/bin/python -B -m cops.mcp
```

Configure your harness to launch that interpreter with arguments
`["-B", "-m", "cops.mcp"]` from the COPS runtime root, or use the standalone
launcher below. Discovery advertises schema-specific tools such as
`cops_soc_next` and `cops_assess_malware_static`, not a generic command runner.
Responses have `structuredContent` and a compact text status. Annotations distinguish
pure transformations and durable state changes. An optional idempotency key
applies only to the corresponding keyed request. Use the documented run ID and
recovery path for an interrupted durable operation.

The SDK is pinned to `mcp==1.30.0` and optional; core operations, scanning,
discovery, and package validation remain standard-library-only. The adapter bounds
frames before SDK parsing and suppresses SDK logs that might echo private values.
It applies a 30-second response deadline. MCP cancellation can suppress the
response while a thread continues. Read persisted status for a submitted run.
Pure direct calls can be resubmitted. Run cancellation controls ledger state and
result publication.

## Standalone distribution

From the reviewed Git checkout, export to a **new** operator-selected directory:

```bash
python3 -m cops.operations.bundle --output ./dist-headless
```

The bundle contains the offline headless runtime, schemas, SOC package and its
locked Sentinel dependency, license notices, and a SHA-256 inventory. It does not contain
an interpreter or the optional SDK. Only Git-indexed files in the selected runtime
and portable SOC inventory are eligible; untracked local evidence is excluded.
Move it to an approved location, then invoke
`python3 /approved/bundle/cops_headless.py tools list --json` from any directory.
For MCP use the same absolute launcher with argument `mcp` and an interpreter
with the optional dependency installed. CLI invocations work without site packages.

Protect the installation against modification. Hashes establish consistency, not
publisher authenticity or a sandbox. Local tools run with the launcher's OS rights.
The bundle exporter is an operator command and is never exposed as an agent tool.
Individual plugin installation does **not** automatically install this shared
runtime. Package `org.cops/operations.json` files declare that prerequisite.

## Completeness and validation

`catalog/operations.json`, `catalog/features.json` and each package's
`org.cops/operations.json` map operations, skills, numbered workflow steps and
statically declared public CLI entrypoints to source digests and support states.
Unresolved dynamic declarations remain explicit. `cops.features.list` supports
package filtering and bounded pagination; `.info` looks up one inventory ID.
Only reviewed handlers are `implemented`. Skills are harness-delegated, while
unmapped prose/CLI steps remain `unsupported`; file presence does not prove a
typed operation exists. The status vocabulary also supports prerequisite-blocked
features without treating installation readiness as an implementation claim.

Packages without typed mappings still say `not_mapped`; mapped packages say
`pilot_mapped` and retain `package_feature_complete: false`. The source inventory
is not a complete product-requirements denominator and does not change existing
diagnostic `ready` states. Unsupported typed steps do not prohibit ad hoc exploration.
Host-installation, synthetic-laboratory and live-provider validation stay separate.

After intentional declaration changes:

```bash
python3 scripts/check_headless_operations.py --generate
make check-headless PYTHON=.venv/bin/python
make check PYTHON=.venv/bin/python
```

The dedicated headless gate requires the optional SDK and tests real stdio
client/server exchange. The portable baseline skips SDK tests if it is absent;
such a skip is not MCP conformance evidence. Other tests exercise all assessment
fixture outcomes, SOC handoff/import/resubmission, malicious arguments, missing
dependencies, cooperative cancellation, informal escalation and standalone export.
