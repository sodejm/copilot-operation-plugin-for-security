---
name: ai-agent-mcp-laboratories
description: Run synthetic local agent and MCP boundary cases and interpret observed fixture effects.
---

# Local agent and MCP laboratories

Use this skill for offline rehearsal of prompt injection and tool authorization boundaries in the Foundry Agent Harness. The agent is a deterministic fixture, not a model or a Microsoft Foundry integration. The MCP server is a fixed local stdio fixture with synthetic state and canary data. Results describe these fixtures only.

## Run

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab --json --output /tmp/cops-agent-mcp-lab-report.json
```

Omit `--json` for a concise summary. `--cases` accepts one case file or a directory of case files conforming to `schemas/lab-case.schema.json`. Use synthetic data only; case text and call arguments appear in reports. Do not add credentials, private data, or live endpoints.

Inspect `environment_verified`, `cleanup_verified`, and `expectation_met` for every result. Read `model_text`, `attempted_calls`, `denied_calls`, `executed_calls`, and `executed_effects` as separate evidence. An attempted call is not an effect. An executed call can be a read with no effect. Effects are determined from MCP state before and after execution. The baseline `permission_only` case deliberately permits a synthetic mutation; the paired `strict` case denies it.

For the separate delegation authorization pack, create the immutable batch with `auth-plan`, then obtain and store one signed receipt through the existing COPS authorization workflow. Run `auth-lab` with `--plan`, `--authorization`, `--engagement`, `--trust-store`, `--worker-identity`, and `--approval-store`; see the playbook for the complete command and issuance interfaces. Cases follow `schemas/auth-case.schema.json`; reports follow `schemas/auth-report.schema.json`. Verify the signed assessment binding, pinned fixtures, peer-to-target correlation, decision phase, and independently observed effects. An allowed write requires an effect; a denial requires none. Missing context, observer evidence, or cleanup is inconclusive. Inspect aggregate budgets, pending cases, and the next action. The receipt is consumed once for the batch; interrupted execution requires a new approved plan for pending cases. A COPS receipt cannot replace the target's synthetic grant. This fixture supplies no live-provider, durable-restart, or OS network-isolation evidence.

The runner starts only its bundled Python fixture processes. It does not run user-selected commands, use hosted models or services, or expand authorization to live assessment. Its subprocess boundary is not an OS network sandbox. See `docs/PLAYBOOK.md` for interpretation and `specs/agent-mcp-laboratories.spec.md` for the contract.
