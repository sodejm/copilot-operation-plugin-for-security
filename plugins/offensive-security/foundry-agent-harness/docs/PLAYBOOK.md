# Analyst playbook: synthetic agent and MCP boundary exercises

Use this package to rehearse synthetic prompt injection and authorization boundaries. No workflow runs a hosted model or assesses a deployed Microsoft Foundry or Semantic Kernel agent. Record any real-agent conclusion only from a separately authorized integration test with its own evidence.

## Choose a workflow

The `lab` command starts a deterministic agent fixture and a fixed local MCP stdio server as separate processes. It verifies the server handshake and tool list, observes state before and after a call, and verifies reset. Use it when you need process-backed evidence for the fixture's authorization boundary. The bundled cases include retrieval and tool-response injection, cross-tenant access, peer spoofing, unauthorized mutation and export, memory and context pressure, tool-permission abuse, and authorized controls.

The `evaluate` command runs the older deterministic scenario simulator against an in-memory mock sandbox. Use it to inspect scenario definitions and the simulator's authorization decisions. It does not observe an agent process or MCP transport.

The `auth-plan` command creates an immutable assessment plan for a fixed peer and MCP stdio target fixture. The `auth-lab` command verifies and atomically consumes one signed COPS authorization before importing the bound controller or starting either process. The target separately checks synthetic grant authentication, delegated or autonomous actor binding, audience, tenant, resource, operation, scope, tool permission, and delegation depth. The runner reads a separate canary-write ledger. A COPS execution receipt cannot supply target-service authority.

## Run and inspect delegation authorization

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py auth-plan \
  --plan-id plan-mcp-auth --engagement-id eng-mcp-auth \
  --created-at 2026-10-12T00:00:00Z \
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

Use the same `--cases` selection for planning and execution: one versioned case or a case directory. Case files allow only fixed synthetic aliases, grants, tools, and logical times. Changed cases or fixture sources invalidate the approved manifest. The report is an aggregate `cops.agent-mcp-auth-run/v1` object. `schemas/auth-case.schema.json` and `schemas/auth-report.schema.json` constrain the fixture, while `schemas/auth-adapter.schema.json` and `schemas/auth-evidence.schema.json` define reusable versioned record shapes. Example reports are in `examples/auth-*.json`.

| Integration | Protocol and transport | Pinned identity and permissions | Support |
| --- | --- | --- | --- |
| Bundled fixture | MCP `2025-11-25`, local stdio | `cops-auth-fixture` v1; exact `canary/read` and `canary/write` tool inventory | Synthetic case decisions and canary effects only |
| HTTP or OAuth MCP provider | Unspecified | No provider, client, scopes, or tool list pinned | Unsupported; no live authorization conclusion |

Read each result in this order:

1. Confirm the approved manifest's `adapter` name, version, protocol, and transport, then the result's `environment_verified`. A failed handshake or changed tool inventory is inconclusive.
2. Read the run's `assessment_authorization` separately: signed verification, one-time consumption, plan identity and digest, engagement, and worker. Compare the manifest's approved case attempts with each observation's `peer.forwarded_request`. This authorizes the assessment attempt only; it does not grant the target action.
3. Read each observation's `peer`, `target`, and independently observed effects. The forwarded request records the principal, agent, downstream service, audience, tenant, resource, operation, scopes, tool, and synthetic grant alias. Correlate plan digest, test identity, and attempt, request, and canary IDs across all three sources. A request missing tenant context must be denied with `missing_tenant` and zero effects. Missing target identity telemetry is inconclusive. Hostile peer mutations must not silently become the approved request.
4. Confirm allowed writes in `observed_effects` from the independent ledger. Denials and permitted reads must have no write effect. `cleanup` separately records termination of both processes and removal of temporary storage. Check `outcome`, `evidence_complete`, and `security_pass` as well as `expectation_met`: an intentionally inconclusive test can meet its declared expectation without establishing an authorization boundary. Only a complete passing result sets `security_pass`; the CLI exits nonzero if any result is inconclusive, unsupported, incomplete, cancelled, or failed.
5. Treat `inconclusive` as missing evidence, even if a partial target response was received. For revocation, check the successful write before `revoked_at_tick`, the denial at that tick, and zero effects after it. `revocation_window` declares the bounded logical tick window and observed denial lag; it does not measure provider propagation.

The examples show an authorized delegated write, a wrong-audience denial, and missing target identity telemetry. They establish fixture behavior only. The complete default pack passes all 22 cases, including successful writes in both tenants, cross-tenant denials in both directions, and zero observed effects for all four hostile peer probes. An intentionally inconclusive case can match its declared expectation while returning `security_pass: false` and a nonzero CLI exit. A reusable bearer grant is not assumed to be one-time; `one-time-replay` is a separate synthetic grant policy.

One approval covers the selected batch without per-case prompts. The installed COPS data-only planner validates all case fields without importing any execution file. The trusted bootstrap rebuilds the entire manifest against the six captured source files, verifies and consumes the receipt, then imports a fresh controller and starts processes from the private snapshot. The CLI, bootstrap, COPS data-only planner, verifier and store, Python, and operating system remain trusted installation components. Preloaded controllers and later checkout changes cannot replace approved execution bytes. `source_snapshot` records verification and removal separately from per-case cleanup. Startup registers each process before SIGINT or SIGTERM can interrupt it; cleanup observes process exit and directory removal. SIGKILL or host loss cannot run cleanup, so reconcile any unresolved effects before further approval. At least nine seconds must remain before atomic receipt consumption, including eight seconds reserved for cleanup. A shared ledger counts received response bytes and new independent-ledger bytes across cases; response and ledger reads are limited before they occur. Admission stops at receipt expiry, the aggregate duration deadline, or the observed-output limit. `max_observed_fixture_bytes` bounds admission and received evidence, not the exact serialized report size or subprocess memory. Reports go to stdout, with no `auth-lab` output-file option. Controller initialization exceptions, including `SystemExit`, return redacted failed evidence, nonzero status, and verified snapshot cleanup with the receipt still consumed. Inspect and repair initialization before approving another run when `next_action` is `inspect_execution_initialization_before_new_approval`. Cancellation and stopped admission return partial results, `pending_case_ids`, and a precise `next_action`. The consumed receipt cannot be retried: approve a new plan for pending cases after resolving any reported cleanup failure. This workflow has no durable crash-resume checkpoint and is not the full plain-language coordinator tracked in #283. The approval store requires POSIX ownership and permission checks; this increment claims no Windows runtime acceptance or OS-enforced denied egress.

Package validation and the normal COPS package check read bounded data without importing assessment modules or starting fixtures. Their success establishes package consistency only. When a later case fails unexpectedly, completed results and their budget accounting remain in the partial report. `execution_failure` identifies the failed case, gives a fixed redacted reason, and marks its effects uncertain; subsequent cases are not admitted. Follow `reconcile_uncertain_case_effects_before_new_approval` to resolve those effects before approving pending cases. The consumed receipt cannot authorize an automatic retry.

An external adapter needs a separately reviewed, versioned contract. It must verify COPS signed execution authorization and bind the approved plan to the exact test identity, tenant, resource, action, audience, and requested scope before attempting a call. It must pin the MCP protocol, provider and server identity, tool inventory, and effective permissions, then record redacted authentication and authorization decisions separately from an independent effect observer. Missing identity telemetry, unsupported provider behavior, setup failure, observer failure, timeout, or failed cleanup must yield inconclusive or unsupported evidence. It must measure revocation against a declared bounded window rather than infer propagation from the local logical-time fixture. No external adapter is implemented by this package.

## Run and inspect the laboratory

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab \
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
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py evaluate \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios \
  --json --output /tmp/cops-foundry-scenario-report.json
```

The historical `model_output_only`, `attempted_tool_call`, `denied_tool_call`, and `executed_mock_effect` labels separate simulator text, proposed calls, gate decisions, and local mock operations. The JSON field `model_response_summary` contains simulator output. A denial supports only the claim that this gate rejected this synthetic proposal. A mock effect supports only a local fixture state change. Do not call either a production finding or proof of model robustness.

For a real-agent assessment, document the authorized target, model and tool versions, input provenance, tool call trace, backend authorization decision, and observed side effects separately. No command in this package supplies that evidence.
