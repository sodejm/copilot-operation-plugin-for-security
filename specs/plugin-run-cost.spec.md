# Specification: plugin run cost accounting

## Scope

A reusable contributor skill initially measures COPS executions. Development and
planning are separate run kinds. It works locally without executing a plugin or
calling a paid API. Defaults are three runs weekly and employee rates of $75–150/hour.

## Requirements

- Import only explicitly assigned session windows; include children, retries and
  continuations without counting mirrors, copied logs or inherited fork usage twice.
- Preserve request model and requested effort; effective effort remains unknown
  unless recorded. Missing usage, pricing, tier or source completeness is visible.
- Price each request using an exact, dated provider/model/tier/context rate card.
  Cache reads and writes replace ordinary input; reasoning is already in output.
  Unknown prices are null. API equivalents are never represented as invoices.
- Persist metadata only in an owner-only ledger outside Git working trees;
  imports are atomic, locked, idempotent and reject conflicting ownership.
- Profile bounded local inputs without storing source contents; forecast explicit
  low/base/high request shapes and report assumptions rather than false precision.
- Compare equivalent accepted outcomes across manual, local tools, AI and hybrid
  alternatives, including human review, setup, maintenance and failed attempts.
- Rank measured deterministic opportunities by annual net value and payback;
  distinguish released employee capacity from actual cash savings.

## Verification

Synthetic unit tests in `.agents/skills/plugin-run-cost/tests/` cover accounting,
imports, privacy boundaries, forecasts and economics. Existing session parser
regressions remain required. `make check` is the repository gate. No paid benchmark
or historical COPS execution is fabricated to establish a baseline.
