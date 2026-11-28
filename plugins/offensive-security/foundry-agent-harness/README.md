# Foundry Agent Harness

The Foundry Agent Harness provides offline, synthetic exercises for agent tool authorization and provider response normalization. It does not connect to Microsoft Foundry, Semantic Kernel, a model, a provider API, or a live MCP server. Its results describe the bundled fixtures and gates; they do not measure a deployed agent's prompt injection resistance or provider behavior.

The package has four workflows:

| Workflow | Command | Evidence |
| :--- | :--- | :--- |
| Scenario simulator | `evaluate` | A deterministic scenario decision, authorization decision, and in-memory mock ledger. This legacy workflow does not execute an agent process or model. |
| Local agent and MCP laboratory | `lab` | A deterministic agent fixture proposes calls to a separate, fixed MCP stdio fixture. The runner records proposals, gate denials, calls actually forwarded, observed state effects, and reset verification. |
| Delegation authorization laboratory | `auth-plan`, `auth-lab` | One signed batch approval binds a fixed peer and MCP target fixture. The runner correlates forwarded requests, target decisions, and a separately read canary effect ledger written by a local observer process. |
| AI provider assessment | `python scripts/run_provider_assessment.py` (from the package directory) | Fixed OpenAI, Azure OpenAI, AWS Bedrock, and GCP Vertex shaped response fixtures pass through exact plan binding, post-gate provider-envelope validation, normalization, and the shared assessment budget ledger. No request leaves the host. |

Inventory, data validation, and evaluation do not authorize or prove execution.
Approved isolated execution has separate plan, authorization, worker, observation,
and cleanup gates. There is no general live-agent or live-MCP execution CLI in
this package. A local fixture result is not hosted, provider-backed, production,
or independent human-review evidence.

The worker-only laboratory contract requires registered, versioned adapters and an exact
approval bound to the plan, profile, and `cops.agent-mcp-stdio-envelope/v1`
request. It is limited to local disposable JSONL and MCP stdio fixtures; it is
not a general interface to real endpoints. Unsupported protocol features must be
explicitly rejected. The `foundry.scenario/v2` and
`foundry.execution-trace/v1` contracts distinguish `model_output`,
`tool_call_attempted`, `tool_call_denied`, and `tool_effect_executed`.
Only an independently observed effect supports the last class.

## Design and data flow

Each workflow accepts a versioned synthetic input, applies an authorization or normalization boundary, and emits evidence that distinguishes proposed calls from calls actually forwarded and effects actually observed.

| Contract or artifact | Purpose | Key fields | Producer | Consumer | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- |
| Scenario or laboratory case | Define synthetic content, proposed calls, and expected outcome | Case ID, inputs, tools, policy, expectation | Package maintainer | Simulator or laboratory runner | Schema, unique ID, and expected-outcome checks | Strict case denies a resource change |
| Authorization decision | Record whether a proposed call may cross the gate | Call, policy rule, decision, reason | Gate | Runner and reviewer | Call-to-policy binding and explicit denial reason | Exfiltration proposal denied |
| MCP observation | Separate proposal, forwarding, effect, and cleanup evidence | Attempted, denied, executed calls, state before/after | Fixture MCP process and runner | Laboratory report | Bounded protocol, expected outcome, and full-state reset | Authorized synthetic resource change then reset |
| Provider assessment record | Normalize an admitted provider-shaped fixture | Provider, binding result, usage, tool proposal, budget | Provider assessment runner | Reviewer | Exact request binding, provider schema, and budget checks | AWS fixture reports a tool proposal without execution |
| Playback summary | Qualify scenario coverage and deterministic failure handling | Counts, outcome matrix, rerun comparison, malformed-case result | `scripts/run_playback.py` | Maintainer | Semantic assertions and normalized rerun equality | Six attack proposals attempted and denied |

## Run the delegation authorization laboratory

Run the complete local acceptance demonstration from the repository root:

```bash
.venv/bin/python plugins/offensive-security/foundry-agent-harness/scripts/run_auth_demo.py \
  --output /tmp/cops-agent-mcp-auth-report.json
```

The command invokes the public `auth-plan` and `auth-lab` CLI paths with an ephemeral synthetic
engagement, signing key, verifier trust store, and single-use approval. It executes the fixed
22-case allowed and denied matrix, validates target decisions, all eight observer-ledger effects,
redaction, and cleanup, then invokes the identical `auth-lab` command again and requires the
consumed approval to be denied. The JSON summary records all three CLI exit codes, the stable replay
denial reason, the report path, and its SHA-256; the report is written atomically with mode `0600`
on POSIX hosts.

The provider-neutral observer generates and retains an ephemeral Ed25519 private key inside its
child process. The runner receives only a challenge-bound readiness record and public verification
key, then verifies the observer session, monotonic record sequence, and every signed effect. The
runner therefore cannot mint an accepted observer record with the material it receives. The runner
still controls the trusted source snapshot, child launch, and private work directory on the same
host, so this proves local process-level key separation rather than an independently administered
external authority. It does not claim live-provider authorization or an OS network sandbox. Its
synthetic approval proves the local fixture contract and does not replace production authorization.

These commands require the COPS source checkout and its Python dependencies. The portable plugin's scenario simulator, local laboratory, and package validator continue to run with the standard library alone.

The issue #236 delegation laboratory exercises this bounded MCP protocol surface:

| Protocol | Version exercised | Transport | Fixture evidence | Support boundary |
| :--- | :--- | :--- | :--- | :--- |
| MCP | [`2025-11-25`](https://modelcontextprotocol.io/specification/2025-11-25) (legacy `initialize` handshake) | Local synthetic stdio | Handshake, pinned advertised server name/version, protocol, complete capability object, and complete unpaginated tool descriptors; pagination is rejected. Advertised metadata is not cryptographic server authentication. | Modern `2026-07-28` per-request metadata behavior is unsupported. No live provider, remote HTTP, OAuth, or broad interoperability claim. |

The next two blocks are an operator template for a separately approved run. They
are not a standalone fixture: first create a current engagement, Ed25519 trust
store and signed authorization receipt as described in the linked authorization
workflow, then replace the `/tmp` paths and worker identity with those artifacts.
Use `scripts/run_auth_demo.py` above for the complete runnable synthetic example.

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py auth-plan \
  --plan-id plan-mcp-auth --engagement-id eng-mcp-auth \
  --created-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output /tmp/cops-agent-mcp-auth-plan.json
```

Review the generated plan and issue its signed authorization through the existing [COPS authorization workflow](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/AUTHENTICATED_EXECUTION.md). Store the receipt in the private approval database and bind it to the engagement and worker identity. Then run the approved batch headlessly:

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py auth-lab \
  --plan /tmp/cops-agent-mcp-auth-plan.json \
  --authorization /tmp/cops-agent-mcp-auth-authorization.json \
  --engagement /tmp/cops-agent-mcp-auth-engagement.json \
  --trust-store /tmp/cops-agent-mcp-auth-trust.json \
  --worker-identity fixture-worker --approval-store /tmp/cops-agent-mcp-auth-approvals.sqlite3 \
  --json
```

Use `--cases` for one case or a directory. Inputs follow `schemas/auth-case.schema.json`; reports follow `schemas/auth-report.schema.json`. The separate `schemas/auth-adapter.schema.json`, `schemas/auth-evidence.schema.json`, and `schemas/auth-normalized-observation.schema.json` describe the fixture adapter, fixture evidence, and a provider-neutral redacted observation record. The 22 bundled cases include delegated controls for both tenants, an autonomous control, cross-tenant denials in both directions, audience mismatches, expiry, revocation, one-time replay, excessive delegation depth, and confused-deputy requests. The versioned `schemas/auth-required-coverage.json` matrix binds all 22 required case IDs to their grants, flows, decisions, reasons, and effect counts; omitting or substituting a required case fails package and runtime validation. Four peer probes mutate or omit tenant context, change the operation, or substitute the assessment receipt for a target grant. The ordinary reusable grant is accepted twice; replay rejection is asserted only for the grant marked one-time and only across attempts within the same target process.

Inspect the approved manifest's `adapter` and the run's `assessment_authorization`, `source_snapshot`, `budget`, `pending_case_ids`, `execution_failure`, `recovery_actions`, and `next_action`. Each result records `environment_verified`, `observations` with separate `peer` and `target` records, `normalized_observations` with effect provenance, `observed_effects`, `revocation_window`, `cleanup`, `evidence_complete`, `expectation_met`, and `security_pass`. Every peer request, target decision, and effect is bound to the approved plan digest, test identity, case, principal, tool, and attempt, request, and canary identities. An allowed read requires an observer-ledger disclosure witness, and an allowed write requires an observer-ledger effect; a denial requires neither. The runner verifies each effect with the observer process's Ed25519 public key, challenge-bound session, and monotonic sequence. It cannot sign effects because the child retains the private key. This is not independent external attestation because the runner still controls the approved child code, launch, and same-host work directory. A request missing tenant context is denied with `missing_tenant`. Missing identity telemetry or a positive disclosure or effect witness, an unavailable observer, or failed setup or cleanup is inconclusive. Matching an expected inconclusive result does not set `security_pass`; the CLI exits nonzero for inconclusive, unsupported, incomplete, cancelled, or failed runs. The complete default pack passes all 22 cases, including zero observer-ledger effects for all four hostile peer probes. The revoked-grant case uses synthetic logical time and does not measure provider propagation. Reports use fixed synthetic aliases without bearer tokens or live-provider claims. See [the analyst playbook](docs/PLAYBOOK.md) and the [authorized](examples/auth-authorized.json), [denied](examples/auth-denied.json), and [inconclusive](examples/auth-inconclusive.json) reports.

Package validation and `cops check foundry-agent-harness` inspect bounded configuration, schemas, case definitions, and skill frontmatter without importing assessment modules or launching fixture processes. Schema admission checks every node, including unused definitions, rejects unsupported constraints, and permits only bounded local references. These data checks do not establish runtime behavior; use observed laboratory execution for that evidence. If a later case raises an exception or `SystemExit`, the run retains earlier completed results and their budget usage, stops admitting cases, and records the failed case with uncertain effects in a redacted `execution_failure`. The receipt remains consumed. Follow `reconcile_uncertain_execution_effects_before_new_approval` before approving pending work; the failed case is never retried automatically.

The receipt is consumed atomically once for the whole batch, only when at least nine seconds remain, including eight seconds reserved for cleanup. Case selection, fixture source hashes, identities, and aggregate duration and observed-output limits are immutable approval inputs. The installed COPS data-only planner validates every case field and binds all seven execution files as inert bytes. The trusted bootstrap rebuilds and compares the entire manifest, verifies and consumes authorization, then loads a fresh controller and starts processes from those captured bytes in private storage. An existing controller import or later checkout change cannot replace the approved controller. The bootstrap, CLI, COPS data-only planner, verifier and approval store, Python, and operating system remain trusted installation components. Plan, engagement, receipt, trust, and case inputs use bounded strict JSON. The observed-output limit counts received fixture responses and new ledger bytes, with reads bounded before admission; it does not bound serialized report size or subprocess memory. Reports go to stdout; `auth-lab` has no output-file option. Controller initialization exceptions, including `SystemExit`, return a redacted failed report and nonzero status after checking source-snapshot removal; the receipt remains consumed. `source_snapshot.failures` retains simultaneous initialization and cleanup failures. Ordered `recovery_actions` require effect reconciliation, initialization inspection, and cleanup inspection as applicable before a new plan approval; `next_action` identifies the first outstanding action. SIGINT and SIGTERM cancellation observe child exit and private-directory removal and return partial evidence. SIGKILL or loss of the host cannot run cleanup; inspect unresolved effects before approving further work. Expiry, cancellation, or a budget stop leaves explicit pending cases and requires a new approved plan for those cases; durable restart belongs to #283. The COPS receipt authorizes the assessment only. The target fixture independently verifies its synthetic grant before performing an action. The local processes and declared no-egress plan are not an operating-system network sandbox.

Follow the [end-to-end verification playbook](docs/VERIFICATION.md) to qualify this
package's documented workflow and prepare evidence for a maturity review.

Activate the repository virtual environment before running the portable package baseline commands:

```bash
source .venv/bin/activate
python3 -m cops info foundry-agent-harness
python3 -m cops demo foundry-agent-harness
python3 -m cops check foundry-agent-harness
```

## Run the local laboratory

From the repository root:

```bash
.venv/bin/python plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab
```

Generate a versioned JSON report:

```bash
.venv/bin/python plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab \
  --json --output /tmp/cops-agent-mcp-lab-report.json
```

Use `--cases path/to/case.json` for one case, or `--cases path/to/directory` for a directory. Case inputs follow `schemas/lab-case.schema.json`; output follows `schemas/lab-report.schema.json`. The 13 bundled cases cover retrieved content, tool responses, tenant boundaries, peer messages, state change, exfiltration, memory, context, tool permission, and authorized controls. A permissive synthetic baseline executes a resource change; its paired strict case denies the same proposed call.

For each case, read `model_text`, `attempted_calls`, `denied_calls`, `executed_calls`, and `executed_effects` separately. A proposed call is not an executed call. An executed read need not change state. Effects come from the fixture's observed before and after state. The runner resets and compares the complete MCP state, including any injected tool response note, with the state before case setup. It reports `cleanup_verified`; an unmet expected outcome or failed verification exits nonzero.

The fixed fixture processes have bounded stdio responses and run in a temporary directory. They use only synthetic accounts, resources, and canary data. The process boundary is not an operating-system network sandbox. The report includes case text and arguments, so use synthetic inputs only; do not supply credentials, private data, or live endpoints. The runner accepts no user-selected process command or network destination.

## Run the scenario simulator

```bash
.venv/bin/python plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py list \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios
.venv/bin/python plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py evaluate \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios \
  --json --output /tmp/cops-foundry-scenario-report.json
```

The six legacy scenarios use a deterministic simulator and an in-memory mock sandbox. The `model_response_summary` field is simulator text, despite its historical schema name. An `executed_mock_effect` is a local mock effect, not evidence of a real agent action. The simulator's rollback ledger does not apply to the separate MCP laboratory; the laboratory verifies a fixture reset after each case.

Run the manifest playback to verify all six bundled scenarios, their authorization
outcomes, repeatability, and a malformed-scenario failure path:

```bash
python3 plugins/offensive-security/foundry-agent-harness/scripts/run_playback.py
```

The playback uses copied fixtures in a private temporary directory. It runs the
actual `evaluate` command twice, removes run-specific report identifiers before
comparison, and requires all six synthetic attack proposals to be attempted and
denied with no model or real tool execution. See the [analyst
playbook](docs/PLAYBOOK.md#deterministic-manifest-playback) for the data flow,
schema, result interpretation, and limitations.

## Assess synthetic provider fixtures

From the `foundry-agent-harness` package directory, with a Python virtual environment activated:

```bash
python scripts/run_provider_assessment.py
```

The command imports the bundled plan and 14 response cases. Four success cases use provider-shaped envelopes for OpenAI Responses, Azure OpenAI Responses, AWS Bedrock Converse, and GCP Vertex `generateContent`. The remaining cases exercise endpoint, tenant, model, tool, canary, and request binding; budget refusal; an AWS tool proposal; and an incomplete OpenAI response.

The plan permits only `offline_fixture` mode with paid execution disabled. Environment, scope, endpoint, model, canary, requested tools, and canonical request digest must match before budget reservation. Only an admitted case has its response checked against the strict schema for that provider; malformed or cross-provider envelopes fail instead of being normalized. The report replaces source case IDs with stable SHA-256 references from `report_case_id` and excludes response text, endpoint URLs, account identifiers, and canary values. A partial response retains conservative unknown usage and records no effect. An AWS tool request is reported as `tool_proposal`; the importer never executes it.

Treat `all_expectations_met`, `cleanup_verified`, and `budget.over_budget: false` as fixture checks. A completed run still emits its JSON report but exits nonzero if the ledger is over budget. These fields do not authenticate a provider response, establish actual token usage or cost, prove remote cancellation or cleanup, or authorize live execution. A v2 egress route supports bounded `POST` to an operator gateway, but this offline importer does not use it. The separate gateway components include provider adapters and an emulator for protocol and budget gates; the offline importer does not invoke them. Disposable endpoint-independent tests do not qualify a live provider or authorize paid execution. Repository operators should read `docs/PROVIDER_GATEWAY.md` and `specs/ai-provider-live-gateway.spec.md` from the source checkout. Paid assessment requires a separately reviewed production path and engagement authorization.

See [the analyst playbook](docs/PLAYBOOK.md) for interpreting all four workflows. The repository contracts are `specs/agent-mcp-laboratories.spec.md` and `specs/ai-provider-assessment.spec.md`. From the repository root, activate a Python virtual environment, then validate with `python plugins/offensive-security/foundry-agent-harness/scripts/validate_package.py` and `python -m cops check foundry-agent-harness`.
