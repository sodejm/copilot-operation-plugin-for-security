# Specification: Model and effort routing advice

## Purpose

Extend the shared COPS specialist router with offline, deterministic model and
effort suggestions for plugin and issue work. Host discovery supplies model IDs,
capabilities, availability and access; brand names alone grant no capability.

## Acceptance criteria

1. Both `cops route` and `cops.routing route` accept `--suggest-model`, an optional
   `--model-catalog`, task kind/complexity overrides and current model/effort.
   Existing calls retain their output and authorization behavior.
2. Task classification chooses capability, model tier and effort independently.
   Routine documentation uses general/efficient/low, ordinary coding uses
   coding/balanced/medium, and security review or advanced adversarial research
   benefits from a flagship with the respective capability at high effort.
   Complex coding benefits from a flagship at high effort too.
3. Suggestions use only exact IDs in a strict, operator-supplied catalog observed
   within 24 hours. Every recommended model has explicit availability, granted
   access, sufficient capability/tier and a supported low, medium or high effort.
   Unknown, denied, unavailable, stale and future-dated evidence cannot recommend
   a model. Duplicate IDs or fields and invalid records fail before authorization.
4. Daybreak, Fable, Mythos, Astra and future families can be suggested when their
   catalog records qualify. Their names confer neither security capability nor
   account entitlement. Blue access never implies Red access.
5. Prefer the lowest sufficient tier, then the operator's numeric preference and
   model ID for stable ties. Preference is not measured pricing or a benchmark.
   Never automatically choose xhigh, max or ultra, or silently downgrade a task's
   required capability when no suitable model is available.
6. Explicit current settings are assessed as adequate, change recommended or
   unverified. Unspecified settings remain unknown. Explain recommendations and
   excluded candidates; report when host discovery or a setting change is needed.
7. The advisor does not call a model, probe entitlements, change settings, spawn
   agents, execute catalog content or modify authorization receipts. Suggestions
   are advisory; the host and existing authorization gates remain authoritative.
8. Contributor routing instructions require issue preflight, check current model
   and effort, pause before implementation for a beneficial Daybreak access change,
   and use supported subagent overrides only where the launch surface permits.

## Evidence

Executable scenarios: `specs/features/model_effort_routing.feature`.
Unit and command integration tests cover malformed catalogs, freshness, access,
effort support, current-setting assessment and compatibility with authorization.
