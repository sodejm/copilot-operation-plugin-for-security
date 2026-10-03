---
name: plugin-run-cost
description: Estimate and audit full plugin execution cost from local session usage, exact model and effort evidence, input profiles, and employee or deterministic-tool alternatives. Use for COPS run economics, token accounting, scaling forecasts, and cost optimization; keep development separate.
---

# Plugin run cost

Use local scripts for parsing and arithmetic. Do not execute a plugin, start a paid
benchmark, read unrelated sessions, or change model settings to produce a report.
The initial adapter supports Codex session JSONL and COPS executions; the ledger
and economic model use plugin-neutral fields. This contributor skill depends on
its sibling [session-usage-audit](../session-usage-audit/SKILL.md) parser.

## Workflow

1. Define one run's plugin/version, configuration, scope, acceptance criteria and
   explicit session windows. Classify execution, development or planning. Include
   all child, continuation and retry sessions; label inferred attribution.
2. Follow [accounting and operation](references/accounting.md). Copy the synthetic
   [manifest](examples/manifest.json) into a private directory outside Git, replace
   placeholders, and import only selected local session paths. A chat is not
   automatically a plugin run. Keep source completeness unknown until checked.
3. Run `scripts/run_cost.py profile` on supplied repository, local wiki exports and
   threat-model files. Read compact counts, not raw source content, into context.
4. Report observed runs, then forecast explicitly named low/base/high assumptions
   with the [forecast configuration](examples/forecast.json). Use `--profile` for
   input scaling. Separate historical pricing from explicit current repricing.
5. Use the [business configuration](examples/business.json) for three runs weekly
   and $75–150/hour. Replace synthetic durations and costs with observations.
   Compare the same accepted outcome across manual, local tools, AI and hybrid.
6. Review technical correctness and coverage, business net value, opportunity cost
   of engineering investment, and employee capacity versus cash expenditure.
   Rank measured candidates for deterministic scripts; preserve security judgment
   and quality checks. Never declare repeated calls automatically wasteful.

## Output contract

Return per-run and per-accepted-result cost, model/effort/stage/role breakdown,
pricing basis, token coverage, unpriced reasons, source completeness, input size,
forecast assumptions, human active time and elapsed windows separately. Explain
which evidence is observed, operator-declared, inferred or unavailable. Unknown
charges stay null; a priced subtotal is not the complete bill. State the top
measured optimization opportunities and their payback, or say measurement is
needed. Report missing run membership without inventing historical executions.

The bundled price snapshot expires after its verified day. Refresh against the
linked official pricing source or supply a dated rate card; do not extend validity
silently. No scheduled collector or external telemetry is installed.
