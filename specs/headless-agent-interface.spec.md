# Headless operation interface

## Scope and boundaries

COPS exposes a versioned, standard-library operation service through a JSON CLI
and an optional local stdio MCP adapter. Conversation, model selection, peer-agent
launch, and clarification remain in the harness. No remote MCP listener is added.
The first release covers existing offline artifact assessments and SOC
validate, next, handoff, import, revise, and report operations. Existing CLIs remain
compatible. This is pilot operation coverage, not package-wide feature completion.

## Contracts

- Discovery is inert: it imports no assessment/SOC payload, executes no package
  command, installs nothing, and starts no worker or network connection.
- Declarations bind an immutable operation ID/version to a reviewed implementation,
  input/output schemas, owner, feature/skill references, effects, limits and retry
  semantics. Runtime dispatch is an explicit allowlist, never a supplied import path.
- Invocation accepts one bounded strict JSON object with `schema_version:
  cops.operation-request/v1`, `operation_id`, optional `request_id`, and `arguments`.
  Results use `cops.operation-result/v1` and `succeeded`, `needs_input`, `blocked`,
  `partial`, or `failed`. Invocation success is not a security
  verdict. Errors contain stable codes, not exception text or supplied evidence.
- Tool arguments contain inline JSON/encoded sample bytes, without a host path,
  command, Python module, executable, output destination, or network destination.
  Strings *inside evidence* remain uninterpreted data, including apparent paths.
- Stateless pilot handlers are bounded local transformations, including SOC import
  and revise. They return snapshots and write no files. Callers retain snapshots and
  may safely retry. They confer no live query, sample execution, or mutation authority.
- Exploratory work requires only a task. Artifacts, context, and informal peer notes
  are optional. It requires no Engagement, ActionPlan, recipient or workflow DAG.
  Escalation returns a blocked proposal for human review. The proposal grants no
  authority and cannot become an executable action through this interface.
- Cancellation prevents admission or suppresses a result at a cooperative boundary.
  A running pure transformation may finish in its thread; no cancellation/rollback
  of external effects is claimed. Recovery is resubmission of caller-owned inputs.
- MCP uses the maintained optional Python SDK, schema-specific tool names and the
  same service/schema validation as the CLI. Only stdio is exposed. The adapter
  bounds request frames and serialized output; no startup logs enter stdout.
  MCP retry hints are conservative: durable writes are not
  advertised as idempotent. Optional idempotency keys do not make an unkeyed run,
  operation or delegation creation safe for automatic client retry.

## Distribution and evidence

A deterministic headless bundle includes the service, reviewed Python runtime,
schemas and SOC dependency with a hash inventory. It runs without the source
checkout from an unrelated directory. Per-package feature-operation manifests and
a catalog report distinguish pilot coverage from packages not yet mapped, and
never promote synthetic tests to live-provider or host-installation validation.
Behavioral tests, malformed-input controls, missing-prerequisite rejection,
exploratory escalation, cancellation/retry, SDK client/server exchange and exported
bundle tests run under repository-owned validation. No credentials or approval
signing material for execution approval enter the operation service. The service
has no worker or worker transport configuration.

## Durable local lifecycle extension

The optional installation-owned runtime configuration supplies a private state
directory and an optional installed repository root. Discovery does not open the
database or load configuration. Stateless calls remain available without it.
Configuration with a worker, plan registry or execution backend is rejected.

- `cops.run.create` accepts an allowlisted offline operation request and an
  optional idempotency key. Same-key/same-request submission returns the same
  run. Changed inputs conflict. Each run binds its accepted inputs and operation
  declaration.
- `cops.run.resume` atomically claims one attempt, releases the database lock,
  and dispatches the stored offline operation. Completed results are reused.
  `status`, `cancel`, and `recover` are separate calls. An expired uncancelled
  attempt may be retried. An expired attempt with cancellation intent becomes
  terminal `cancelled` and clears its lease without another handler call.
- Queued cancellation is terminal. Running cancellation records intent and
  suppresses the result. A local transformation may still finish.
- Legacy worker-backed records are refused without dispatch or mutation. The
  interface exposes no worker submission or reconciliation tools and accepts
  no worker authorization.
- State is owner-only POSIX SQLite in an owner-only directory, with no-follow
  path checks and bounded documents and capacity. Unsupported platforms fail
  closed for persistence. The state owner retains filesystem control.

## Delegation and completeness extension

Optional delegation binds a task, scope alias, selected specialist, installed product
skill digest and permitted operation to a stored opaque delegation ID. Product skills
resolve before contributor fallbacks. A response must match the exact binding and
operation contract, be accepted once, and pass current implementation revalidation.
It remains untrusted peer evidence, never execution proof or authority. Task-only
work and informal notes do not need this protocol.

Feature inventory covers each product skill, its numbered workflow steps, and each
statically declared public Python CLI subcommand. Every row records source digest,
reference and headless status: implemented, externally_delegated,
blocked_by_prerequisite or unsupported. Dynamic CLI declarations are explicitly
unresolved, not silently omitted. Only reviewed operation mappings establish
implemented status; reasoning and unmapped CLI steps do not become implementations
because their files exist. Generation/validation catches new or changed inventory
and preserves false package-completion states while unsupported work remains.
Remote hosting, live-provider qualification and independent review remain separate.
