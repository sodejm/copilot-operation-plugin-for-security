# Foundry Agent Harness

The Foundry Agent Harness provides offline, synthetic exercises for agent tool authorization. It does not connect to Microsoft Foundry, Semantic Kernel, a model, or a live MCP server. Its results describe the bundled fixtures and gates; they do not measure a deployed agent's prompt injection resistance.

The package has three workflows:

| Workflow | Command | Evidence |
| :--- | :--- | :--- |
| Scenario simulator | `evaluate` | A deterministic scenario decision, authorization decision, and in-memory mock ledger. This legacy workflow does not execute an agent process or model. |
| Local agent and MCP laboratory | `lab` | A deterministic agent fixture proposes calls to a separate, fixed MCP stdio fixture. The runner records proposals, gate denials, calls actually forwarded, observed state effects, and reset verification. |
| Delegation authorization laboratory | `auth-plan`, `auth-lab` | One signed batch approval binds a fixed peer and MCP target fixture. The runner correlates forwarded requests, target decisions, and an independently read canary effect ledger. |

## Run the delegation authorization laboratory

These commands require the COPS source checkout and its Python dependencies. The portable plugin's scenario simulator, local laboratory, and package validator continue to run with the standard library alone.

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py auth-plan \
  --plan-id plan-mcp-auth --engagement-id eng-mcp-auth \
  --created-at 2026-10-12T00:00:00Z \
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

Use `--cases` for one case or a directory. Inputs follow `schemas/auth-case.schema.json`; reports follow `schemas/auth-report.schema.json`. The separate `schemas/auth-adapter.schema.json` and `schemas/auth-evidence.schema.json` describe the versioned adapter and redacted observation records. The 22 bundled cases include delegated controls for both tenants, an autonomous control, cross-tenant denials in both directions, audience mismatches, expiry, revocation, one-time replay, excessive delegation depth, and confused-deputy requests. Four peer probes mutate or omit tenant context, change the operation, or substitute the assessment receipt for a target grant. The ordinary reusable grant is accepted twice; replay rejection is asserted only for the grant marked one-time.

Inspect the approved manifest's `adapter` and the run's `assessment_authorization`, `source_snapshot`, `budget`, `pending_case_ids`, and `next_action`. Each result records `environment_verified`, `observations` with separate `peer` and `target` records, `observed_effects`, `revocation_window`, `cleanup`, `evidence_complete`, `expectation_met`, and `security_pass`. Every peer request, target decision, and effect is bound to the approved plan digest and test, attempt, request, and canary identities. An allowed write requires an independently observed effect; a denial requires none. A request missing tenant context is denied with `missing_tenant`. Missing identity telemetry, an unavailable observer, or failed setup or cleanup is inconclusive. Matching an expected inconclusive result does not set `security_pass`; the CLI exits nonzero for inconclusive, unsupported, incomplete, cancelled, or failed runs. The complete default pack passes all 22 cases, including independently observed zero effects for all four hostile peer probes. The revoked-grant case uses synthetic logical time and does not measure provider propagation. Reports use fixed synthetic aliases without bearer tokens or live-provider claims. See [the analyst playbook](docs/PLAYBOOK.md) and the [authorized](examples/auth-authorized.json), [denied](examples/auth-denied.json), and [inconclusive](examples/auth-inconclusive.json) reports.

The receipt is consumed atomically once for the whole batch, only when at least nine seconds remain, including eight seconds reserved for cleanup. Case selection, fixture source hashes, identities, and aggregate duration and observed-output limits are immutable approval inputs. The installed COPS data-only planner validates every case field and binds all six execution files as inert bytes. The trusted bootstrap rebuilds and compares the entire manifest, verifies and consumes authorization, then loads a fresh controller and starts processes from those captured bytes in private storage. An existing controller import or later checkout change cannot replace the approved controller. The bootstrap, CLI, COPS data-only planner, verifier and approval store, Python, and operating system remain trusted installation components. Plan, engagement, receipt, trust, and case inputs use bounded strict JSON. The observed-output limit counts received fixture responses and new ledger bytes, with reads bounded before admission; it does not bound serialized report size or subprocess memory. Reports go to stdout; `auth-lab` has no output-file option. Controller initialization exceptions, including `SystemExit`, return a redacted failed report and nonzero status after verifying source-snapshot removal; the receipt remains consumed and `next_action` requires inspection of execution initialization before new approval. SIGINT and SIGTERM cancellation observe child exit and private-directory removal and return partial evidence. SIGKILL or loss of the host cannot run cleanup; inspect unresolved effects before approving further work. Expiry, cancellation, or a budget stop leaves explicit pending cases and requires a new approved plan for those cases; durable restart belongs to #283. The COPS receipt authorizes the assessment only. The target fixture independently verifies its synthetic grant before performing an action. The local processes and declared no-egress plan are not an operating-system network sandbox.

Follow the [end-to-end verification playbook](docs/VERIFICATION.md) to qualify this
package's documented workflow and prepare evidence for a maturity review.

## Run the local laboratory

From the repository root:

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab
```

Generate a versioned JSON report:

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab \
  --json --output /tmp/cops-agent-mcp-lab-report.json
```

Use `--cases path/to/case.json` for one case, or `--cases path/to/directory` for a directory. Case inputs follow `schemas/lab-case.schema.json`; output follows `schemas/lab-report.schema.json`. The 13 bundled cases cover retrieved content, tool responses, tenant boundaries, peer messages, state change, exfiltration, memory, context, tool permission, and authorized controls. A permissive synthetic baseline executes a resource change; its paired strict case denies the same proposed call.

For each case, read `model_text`, `attempted_calls`, `denied_calls`, `executed_calls`, and `executed_effects` separately. A proposed call is not an executed call. An executed read need not change state. Effects come from the fixture's observed before and after state. The runner resets and compares the complete MCP state, including any injected tool response note, with the state before case setup. It reports `cleanup_verified`; an unmet expected outcome or failed verification exits nonzero.

The fixed fixture processes have bounded stdio responses and run in a temporary directory. They use only synthetic accounts, resources, and canary data. The process boundary is not an operating-system network sandbox. The report includes case text and arguments, so use synthetic inputs only; do not supply credentials, private data, or live endpoints. The runner accepts no user-selected process command or network destination.

## Run the scenario simulator

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py list \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py evaluate \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios \
  --json --output /tmp/cops-foundry-scenario-report.json
```

The six legacy scenarios use a deterministic simulator and an in-memory mock sandbox. The `model_response_summary` field is simulator text, despite its historical schema name. An `executed_mock_effect` is a local mock effect, not evidence of a real agent action. The simulator's rollback ledger does not apply to the separate MCP laboratory; the laboratory verifies a fixture reset after each case.

See [the analyst playbook](docs/PLAYBOOK.md) for interpreting both workflows. The repository specification is `specs/agent-mcp-laboratories.spec.md`. Validate with `python3 plugins/offensive-security/foundry-agent-harness/scripts/validate_package.py` and `python3 -m cops check foundry-agent-harness`.
