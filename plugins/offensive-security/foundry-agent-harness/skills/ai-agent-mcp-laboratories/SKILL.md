---
name: ai-agent-mcp-laboratories
description: "Use for requests to test this AI tool integration in a local lab. Run synthetic local agent and MCP boundary cases and interpret observed fixture effects."
---

# Local agent and MCP laboratories

Use this skill for offline rehearsal of prompt injection and tool authorization boundaries in the Foundry Agent Harness. The agent is a deterministic fixture, not a model or a Microsoft Foundry integration. The MCP server is a fixed local stdio fixture with synthetic state and canary data. Results describe these fixtures only.

Inventory and evaluation are data-only activities; they do not authorize or establish execution. A separate isolated execution requires an exact reviewed plan, signed authorization, a verified worker and isolation boundary, independent observation, and verified cleanup. There is no general live-agent or live-MCP CLI in this package. Do not treat fixture output or an expected denial as evidence that a deployed system is secure.

The worker-only contract requires registered, versioned adapters and approval bound to the exact plan, profile, and `cops.agent-mcp-stdio-envelope/v1` request. Its scope is local disposable JSONL and MCP stdio fixtures, not real endpoints. Unsupported protocol features must produce explicit rejection evidence. Trace classes have distinct meanings: `model_output` is text, `tool_call_attempted` is a proposal, `tool_call_denied` is a rejected proposal, and `tool_effect_executed` requires an observed effect. The versioned scenario and trace contracts are `foundry.scenario/v2` and `foundry.execution-trace/v1`.

The executable contract requires one bounded JSONL request and response per operation, or the MCP stdio sequence `initialize`, `notifications/initialized`, `tools/list`, and one exact-approved `tools/call`. Network transports, server-initiated requests, sampling, roots, prompts, resources, subscriptions, elicitation, extensions, capability expansion, duplicate or unknown IDs, malformed or oversized messages, extra output, and calls outside the envelope must be rejected. See the playbook for interpretation; this is not a general MCP interoperability claim.

## Run

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab --json --output /tmp/cops-agent-mcp-lab-report.json
```

Omit `--json` for a concise summary. `--cases` accepts one case file or a directory of case files conforming to `schemas/lab-case.schema.json`. Use synthetic data only; case text and call arguments appear in reports. Do not add credentials, private data, or live endpoints.

Inspect `environment_verified`, `cleanup_verified`, and `expectation_met` for every result. Read `model_text`, `attempted_calls`, `denied_calls`, `executed_calls`, and `executed_effects` as separate evidence. An attempted call is not an effect. An executed call can be a read with no effect. Effects are determined from MCP state before and after execution. The baseline `permission_only` case deliberately permits a synthetic mutation; the paired `strict` case denies it.

Keep vulnerable, negative-control, and remediated observations distinct: a vulnerable case needs an observed effect, a negative control needs the expected benign behavior, and a remediated case needs evidence that the same bounded attempt no longer produces the effect. Missing observation, isolation, or cleanup evidence is inconclusive; an evaluation or a matching expectation alone does not establish those outcomes. Reconcile uncertain effects before a new approval.

For the separate delegation authorization pack, create the immutable batch with `auth-plan`, then obtain and store one signed receipt through the existing COPS authorization workflow. Run `auth-lab` with `--plan`, `--authorization`, `--engagement`, `--trust-store`, `--worker-identity`, and `--approval-store`; see the playbook for the complete command and issuance interfaces. Cases follow `schemas/auth-case.schema.json`; reports follow `schemas/auth-report.schema.json`. Verify the signed assessment binding, pinned fixtures, peer-to-target correlation, decision phase, normalized observation provenance, and local observer-ledger effects. An allowed write requires an effect; a denial requires none. Missing context, observer evidence, or cleanup is inconclusive. Inspect aggregate budgets, pending cases, and the next action. The receipt is consumed once for the batch; interrupted execution requires a new approved plan for pending cases. A COPS receipt cannot replace the target's synthetic grant. This fixture supplies no live-provider, durable-restart, or OS network-isolation evidence.

The runner starts only its bundled Python fixture processes. It does not run user-selected commands, use hosted models or services, or expand authorization to live assessment. Its subprocess boundary is not an OS network sandbox. See `docs/PLAYBOOK.md` for interpretation and `specs/agent-mcp-laboratories.spec.md` for the contract.
