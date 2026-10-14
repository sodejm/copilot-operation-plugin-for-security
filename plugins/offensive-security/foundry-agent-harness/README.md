# Foundry Agent Harness

The Foundry Agent Harness provides offline, synthetic exercises for agent tool authorization and provider response normalization. It does not connect to Microsoft Foundry, Semantic Kernel, a model, a provider API, or a live MCP server. Its results describe the bundled fixtures and gates; they do not measure a deployed agent's prompt injection resistance or provider behavior.

The package has three workflows:

| Workflow | Command | Evidence |
| :--- | :--- | :--- |
| Scenario simulator | `evaluate` | A deterministic scenario decision, authorization decision, and in-memory mock ledger. This legacy workflow does not execute an agent process or model. |
| Local agent and MCP laboratory | `lab` | A deterministic agent fixture proposes calls to a separate, fixed MCP stdio fixture. The runner records proposals, gate denials, calls actually forwarded, observed state effects, and reset verification. |
| AI provider assessment | `python scripts/run_provider_assessment.py` (from the package directory) | Fixed OpenAI, Azure OpenAI, AWS Bedrock, and GCP Vertex shaped response fixtures pass through exact plan binding, post-gate provider-envelope validation, normalization, and the shared assessment budget ledger. No request leaves the host. |

## Design and data flow

Each workflow accepts a versioned synthetic input, applies an authorization or normalization boundary, and emits evidence that distinguishes proposed calls from calls actually forwarded and effects actually observed.

| Contract or artifact | Purpose | Key fields | Producer | Consumer | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- |
| Scenario or laboratory case | Define synthetic content, proposed calls, and expected outcome | Case ID, inputs, tools, policy, expectation | Package maintainer | Simulator or laboratory runner | Schema, unique ID, and expected-outcome checks | Strict case denies a resource change |
| Authorization decision | Record whether a proposed call may cross the gate | Call, policy rule, decision, reason | Gate | Runner and reviewer | Call-to-policy binding and explicit denial reason | Exfiltration proposal denied |
| MCP observation | Separate proposal, forwarding, effect, and cleanup evidence | Attempted, denied, executed calls, state before/after | Fixture MCP process and runner | Laboratory report | Bounded protocol, expected outcome, and full-state reset | Authorized synthetic resource change then reset |
| Provider assessment record | Normalize an admitted provider-shaped fixture | Provider, binding result, usage, tool proposal, budget | Provider assessment runner | Reviewer | Exact request binding, provider schema, and budget checks | AWS fixture reports a tool proposal without execution |
| Playback summary | Qualify scenario coverage and deterministic failure handling | Counts, outcome matrix, rerun comparison, malformed-case result | `scripts/run_playback.py` | Maintainer | Semantic assertions and normalized rerun equality | Six attack proposals attempted and denied |

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

Treat `all_expectations_met`, `cleanup_verified`, and `budget.over_budget: false` as fixture checks. A completed run still emits its JSON report but exits nonzero if the ledger is over budget. These fields do not authenticate a provider response, establish actual token usage or cost, prove remote cancellation or cleanup, or authorize live execution. The current shared egress broker supports only `GET` and `HEAD`, so it cannot dispatch provider inference requests. Live or paid assessment requires a separately reviewed execution path and authorization.

See [the analyst playbook](docs/PLAYBOOK.md) for interpreting all three workflows. The repository contracts are `specs/agent-mcp-laboratories.spec.md` and `specs/ai-provider-assessment.spec.md`. From the repository root, activate a Python virtual environment, then validate with `python plugins/offensive-security/foundry-agent-harness/scripts/validate_package.py` and `python -m cops check foundry-agent-harness`.
