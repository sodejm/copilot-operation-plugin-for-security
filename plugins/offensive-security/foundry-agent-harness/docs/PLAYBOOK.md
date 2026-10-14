# Analyst playbook: synthetic agent, MCP, and provider boundary exercises

Use this package to rehearse how local gates handle synthetic prompt injection proposals and provider-shaped response fixtures. None of these workflows runs a hosted model, calls a provider API, or assesses a deployed Microsoft Foundry or Semantic Kernel agent. Record any real-agent or provider conclusion only from a separately authorized integration test with its own evidence.

## Choose a workflow

The `lab` command starts a deterministic agent fixture and a fixed local MCP stdio server as separate processes. It verifies the server handshake and tool list, observes state before and after a call, and verifies reset. Use it when you need process-backed evidence for the fixture's authorization boundary. The bundled cases include retrieval and tool-response injection, cross-tenant access, peer spoofing, unauthorized mutation and export, memory and context pressure, tool-permission abuse, and authorized controls.

The `evaluate` command runs the older deterministic scenario simulator against an in-memory mock sandbox. Use it to inspect scenario definitions and the simulator's authorization decisions. It does not observe an agent process or MCP transport.

The AI provider assessment command imports fixed response envelopes shaped like OpenAI Responses, Azure OpenAI Responses, AWS Bedrock Converse, and GCP Vertex `generateContent`. Use it to inspect exact plan binding, strict post-gate envelope validation, common outcome normalization, and budget-ledger behavior. It has no provider client, credential lookup, network operation, or live mode.

The `auth-plan` command creates an immutable assessment plan for a fixed peer and MCP stdio target fixture. The `auth-lab` command verifies and atomically consumes one signed COPS authorization before importing the bound controller or starting either process. The target separately checks synthetic grant authentication, delegated or autonomous actor binding, audience, tenant, resource, operation, scope, tool permission, and delegation depth. The runner reads a separate canary disclosure and write ledger. A COPS execution receipt cannot supply target-service authority.

## Run and inspect delegation authorization

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py auth-plan \
  --plan-id plan-mcp-auth --engagement-id eng-mcp-auth \
  --created-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output /tmp/cops-agent-mcp-auth-plan.json
```

Review the exact plan, including selected cases, fixture source hashes, tool inventory, synthetic identities, and aggregate limits. Use `cops.execution.authorization.request_interactive_plan_authorization` with the engagement, signer, and bound worker identity, then `ApprovalStore.store_authorization` to persist the receipt. Provision the verifier trust store and signing material as described in [Authenticated execution](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/AUTHENTICATED_EXECUTION.md). These existing Python interfaces supply issuance; the plugin has no separate approval-issuance CLI. The trust store and approval database must be private, owned regular files. No real target credential is needed for this synthetic fixture.

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py auth-lab \
  --plan /tmp/cops-agent-mcp-auth-plan.json \
  --authorization /tmp/cops-agent-mcp-auth-authorization.json \
  --engagement /tmp/cops-agent-mcp-auth-engagement.json \
  --trust-store /tmp/cops-agent-mcp-auth-trust.json \
  --worker-identity fixture-worker --approval-store /tmp/cops-agent-mcp-auth-approvals.sqlite3 \
  --json
```

Use the same `--cases` selection for planning and execution: one versioned case or a case directory. Case files allow only fixed synthetic aliases, grants, tools, and logical times. Changed cases or fixture sources invalidate the approved manifest. The report is an aggregate `cops.agent-mcp-auth-run/v1` object. `schemas/auth-case.schema.json` and `schemas/auth-report.schema.json` constrain the fixture, while `schemas/auth-adapter.schema.json` and `schemas/auth-evidence.schema.json` define fixture records; `schemas/auth-normalized-observation.schema.json` defines the provider-neutral mapping and its effect provenance. Example reports are in `examples/auth-*.json`.

| Integration | Protocol and transport | Pinned identity and permissions | Support |
| --- | --- | --- | --- |
| Bundled fixture | MCP `2025-11-25`, local stdio | `cops-auth-fixture` v1; exact `canary/read` and `canary/write` tool inventory | Synthetic case decisions and canary effects only |
| HTTP or OAuth MCP provider | Unspecified | No provider, client, scopes, or tool list pinned | Unsupported; no live authorization conclusion |

Read each result in this order:

1. Confirm the approved manifest's `adapter` name, version, protocol, and transport, then the result's `environment_verified`. A failed handshake or changed tool inventory is inconclusive.
2. Read the run's `assessment_authorization` separately: signed verification, one-time consumption, plan identity and digest, engagement, and worker. Compare the manifest's approved case attempts with each observation's `peer.forwarded_request`. This authorizes the assessment attempt only; it does not grant the target action.
3. Read each observation's `peer`, `target`, `normalized_observations`, and target-ledger effects. The forwarded request records the principal, agent, downstream service, audience, tenant, resource, operation, scopes, tool, and synthetic grant alias. Correlate plan digest, test identity, case, principal, tool, and attempt, request, and canary IDs across all three sources. A request missing tenant context must be denied with `missing_tenant` and zero effects. Missing target identity telemetry is inconclusive. Hostile peer mutations must not silently become the approved request.
4. Confirm permitted read disclosures and writes in `observed_effects` from the target-produced ledger, which the runner reads separately from tool replies. This is not an independent external effect attestation. Denials must have neither a disclosure nor a write effect; a permitted call without its positive witness is inconclusive. `cleanup` separately records termination of both processes and removal of temporary storage. Check `outcome`, `evidence_complete`, and `security_pass` as well as `expectation_met`: an intentionally inconclusive test can meet its declared expectation without establishing an authorization boundary. Only a complete passing result sets `security_pass`; the CLI exits nonzero if any result is inconclusive, unsupported, incomplete, cancelled, or failed.
5. Treat `inconclusive` as missing evidence, even if a partial target response was received. For revocation, check the successful write before `revoked_at_tick`, the denial at that tick, and zero effects after it. `revocation_window` declares the bounded logical tick window and observed denial lag; it does not measure provider propagation.

The examples show an authorized delegated write, a wrong-audience denial, and missing target identity telemetry. They establish fixture behavior only. The complete default pack passes all 22 cases, including successful writes in both tenants, cross-tenant denials in both directions, and zero observed effects for all four hostile peer probes. An intentionally inconclusive case can match its declared expectation while returning `security_pass: false` and a nonzero CLI exit. A reusable bearer grant is not assumed to be one-time; `one-time-replay` is a separate synthetic grant policy tested across attempts within the same target process.

One approval covers the selected batch without per-case prompts. The installed COPS data-only planner validates all case fields without importing any execution file. The trusted bootstrap rebuilds the entire manifest against the six captured source files, verifies and consumes the receipt, then imports a fresh controller and starts processes from the private snapshot. The CLI, bootstrap, COPS data-only planner, verifier and store, Python, and operating system remain trusted installation components. Preloaded controllers and later checkout changes cannot replace approved execution bytes. `source_snapshot` records verification and removal separately from per-case cleanup; its `failures` array retains every snapshot failure. `recovery_actions` lists outstanding actions in order and `next_action` identifies the first. Startup registers each process before SIGINT or SIGTERM can interrupt it; cleanup observes process exit and directory removal. SIGKILL or host loss cannot run cleanup, so reconcile any unresolved effects before further approval. At least nine seconds must remain before atomic receipt consumption, including eight seconds reserved for cleanup. A shared ledger counts received response bytes and new target-ledger bytes across cases; response and ledger reads are limited before they occur. Admission stops at receipt expiry, the aggregate duration deadline, or the observed-output limit. `max_observed_fixture_bytes` bounds admission and received evidence, not the exact serialized report size or subprocess memory. Reports go to stdout, with no `auth-lab` output-file option. Controller initialization exceptions, including `SystemExit`, return redacted failed evidence and nonzero status with the receipt still consumed. Snapshot removal is independently checked; failed cleanup remains visible alongside initialization failure. Follow every ordered `recovery_actions` entry before approving another run. Cancellation and stopped admission return partial results, `pending_case_ids`, and a precise `next_action`. The consumed receipt cannot be retried: approve a new plan for pending cases after resolving any reported cleanup failure. This workflow has no durable crash-resume checkpoint and is not the full plain-language coordinator tracked in #283. The approval store requires POSIX ownership and permission checks; this increment claims no Windows runtime acceptance or OS-enforced denied egress.

Package validation and the normal COPS package check read bounded data without importing assessment modules or starting fixtures. They structurally check every schema node, including unused definitions, reject unsupported constraints, and bound local reference traversal. Their success establishes package consistency only. When a later case fails unexpectedly, completed results and their budget accounting remain in the partial report. `execution_failure` identifies the failed case, gives a fixed redacted reason, and marks its effects uncertain; subsequent cases are not admitted. Follow `reconcile_uncertain_execution_effects_before_new_approval` to resolve those effects before approving pending cases. The consumed receipt cannot authorize an automatic retry.

An external adapter needs a separately reviewed, versioned contract. It must verify COPS signed execution authorization and bind the approved plan to the exact test identity, tenant, resource, action, audience, and requested scope before attempting a call. It must pin the MCP protocol, provider and server identity, tool inventory, and effective permissions, then record redacted authentication and authorization decisions separately from an independent effect observer. Missing identity telemetry, unsupported provider behavior, setup failure, observer failure, timeout, or failed cleanup must yield inconclusive or unsupported evidence. It must measure revocation against a declared bounded window rather than infer propagation from the local logical-time fixture. No external adapter is implemented by this package.

## Run and inspect the laboratory

```bash
.venv/bin/python plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab \
  --json --output /tmp/cops-agent-mcp-lab-report.json
```

Use `--cases` to select a bundled case or a directory of versioned case JSON files. The runner rejects unsupported tools, tenants, resources, destinations, argument shapes, and arbitrary commands. Use synthetic text only: case text and tool arguments are present in the JSON report. Do not insert credentials, personal data, or live service addresses.

Read each result in this order:

1. Check `environment_verified`, `cleanup_verified`, and `expectation_met`. If any fails, do not use the case as evidence of the expected boundary behavior.
2. Read `model_text` as output from the deterministic proposal fixture. It is not a model response.
3. Read `attempted_calls` as proposals. `denied_calls` were rejected by the independent gate and were not forwarded to MCP.
4. Read `executed_calls` as calls the fixture server handled. A read may produce no effect. Confirm a mutation or export with `executed_effects` and the before and after state, not with response text alone.
5. Compare `state-change-baseline` and `state-change-remediated`. Both receive the same injected proposal. The `permission_only` baseline deliberately permits a synthetic change; the `strict` profile binds the call to the trusted task and denies that proposal. This comparison demonstrates the fixture gate design, not a real-agent exploit or fix.

The runner resets the MCP fixture after every case. It does not use a live MCP endpoint, hosted model, or user-supplied executable. Its subprocess separation and temporary directory are not an operating-system network sandbox.

## Inspect the legacy scenario simulator

```bash
.venv/bin/python plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py evaluate \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios \
  --json --output /tmp/cops-foundry-scenario-report.json
```

The historical `model_output_only`, `attempted_tool_call`, `denied_tool_call`, and `executed_mock_effect` labels separate simulator text, proposed calls, gate decisions, and local mock operations. The JSON field `model_response_summary` contains simulator output. A denial supports only the claim that this gate rejected this synthetic proposal. A mock effect supports only a local fixture state change. Do not call either a production finding or proof of model robustness.

For a real-agent assessment, document the authorized target, model and tool versions, input provenance, tool call trace, backend authorization decision, and observed side effects separately. No command in this package supplies that evidence.

## Inspect the provider assessment fixture

From the `foundry-agent-harness` package directory, with a Python virtual environment activated:

```bash
python scripts/run_provider_assessment.py
```

The default command reads the bundled `provider_fixtures/plan.json` and `provider_fixtures/cases.json`. Use `--plan` and `--cases` only with reviewed, synthetic copies that conform to the package schemas. The bounded loader rejects duplicate keys, unknown fields, excessive nesting, oversized input, and unsupported provider families.

Review results in this order:

1. Require report-level `all_expectations_met` and `cleanup_verified` to be true and `budget.over_budget` to be false. A completed run emits the report but exits nonzero when any of these conditions fails. Cleanup covers the temporary local budget ledger only.
2. Read `decision` before response fields. A case whose environment, account or tenant, project or subscription, region, endpoint, model, canary, tool allowlist, or canonical request digest differs from the plan is `denied` before budget reservation and response processing.
3. Treat `budget_denied` as refusal before fixture processing. The synthetic cost and token estimates are test metadata, not provider price or billing evidence.
4. Only an authorized, budget-admitted case reaches strict response validation. OpenAI and Azure require their status/output envelope, AWS requires its stop reason/message content envelope, and GCP requires its single-candidate content/finish-reason envelope. Unknown fields, unsupported shapes, provider mismatches, and inconsistent tool-use structure fail the assessment before normalization.
5. Interpret `response_state` through the validated provider-specific envelope: completed OpenAI or Azure status, AWS `end_turn`, and GCP `STOP` normalize to `completed`; AWS `tool_use` normalizes to `tool_proposal`; other accepted states normalize conservatively to `partial`.
6. Treat `tool_proposal` as data. This importer has no executor and does not perform the proposed call.
7. For a partial response, require `outcome: no_effect`, `usage_state: unknown`, and a conservative ledger state. Do not infer success from partial text.
8. Confirm `expectation_met` for every case. Result `case_id` values are stable SHA-256 references produced by `report_case_id`, not source case IDs; they support correlation but do not provide anonymity. The report deliberately excludes response content, prompts, endpoints, account identifiers, canaries, and credentials.

The four provider families share one plan and report vocabulary, but their input envelopes are validated and normalized separately. This demonstrates deterministic fixture handling only. It cannot authenticate a provider response, verify tenant identity, establish actual usage or cost, prove remote cancellation or cleanup, or measure model safety. The shared egress broker permits only `GET` and `HEAD` and cannot carry provider inference requests; no live or paid command is available here.
