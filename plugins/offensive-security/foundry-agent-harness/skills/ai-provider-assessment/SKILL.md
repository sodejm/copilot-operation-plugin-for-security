---
name: ai-provider-assessment
description: Inspect offline provider-shaped response fixtures under exact plan and budget controls.
---

# Offline AI provider assessment

Use this skill to inspect the Foundry Agent Harness's fixed synthetic response fixtures for OpenAI Responses, Azure OpenAI Responses, AWS Bedrock Converse, and GCP Vertex `generateContent`. The workflow has no provider client, credential lookup, network operation, tool executor, live mode, or paid mode. Its results describe local fixture handling only.

## Run

From the `foundry-agent-harness` package directory, with a Python virtual
environment activated:

```bash
python scripts/run_provider_assessment.py
```

The default command loads the bundled `provider_fixtures/plan.json` and `provider_fixtures/cases.json`. Use `--plan` and `--cases` only for reviewed synthetic copies that conform to the package schemas. Never place credentials, private prompts, real endpoints, tenant data, or provider output in these files.

## Interpret the report

Require report-level `all_expectations_met` and `cleanup_verified` and require `budget.over_budget` to be false, then inspect every result. A completed run emits its JSON report but exits nonzero on budget overrun. Read `decision` before response fields: exact environment, scope, endpoint, model, canary, requested tools, and canonical request digest must match before budget reservation or response processing. Read `budget_denied` as refusal before fixture processing.

Only authorized, budget-admitted cases have response envelopes validated. Strict provider-specific schemas reject malformed, unknown-field, cross-provider, unsupported-status, inconsistent AWS tool-use, and invalid usage-count envelopes before normalization. OpenAI and Azure `completed`, AWS `end_turn`, and GCP `STOP` become `completed`. AWS `tool_use` becomes `tool_proposal` and is never executed. Other accepted states are conservative `partial` outcomes. A partial result must record `no_effect`, `unknown` usage, and a conservative ledger state.

Result `case_id` values are deterministic SHA-256 references produced by `report_case_id`; the report does not expose source case IDs. These stable pseudonyms support correlation and do not provide anonymity. The report allowlist excludes prompts, response text, endpoint URLs, account identifiers, canary values, and credentials. Synthetic token counts and prices are test metadata. Cleanup covers the temporary local budget ledger. A passing run does not authenticate a provider response, verify tenant identity, establish actual usage or cost, prove remote cancellation or cleanup, or measure model safety.

The shared egress broker permits only `GET` and `HEAD`, so it cannot dispatch provider inference requests. Any live or paid provider assessment needs a separately authorized and reviewed execution boundary with exact request and identity binding.

See `docs/PLAYBOOK.md` for evidence rules, `docs/VERIFICATION.md` for acceptance checks, and `specs/ai-provider-assessment.spec.md` for the repository contract.
