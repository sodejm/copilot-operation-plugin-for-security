# COPS repository layout

| Path | Responsibility |
| --- | --- |
| `README.md`, `docs/GETTING_STARTED.md` | Analyst-first discovery and safe first use |
| `agents/` | Centralized specialist agent profiles (`profiles/*.agent.md`) and canonical registry (`registry.json`) |
| `cops/` | Standard-library catalog, validation, command safety, demos, and checks; optional signing uses `cryptography` |
| `cops/contracts/` | Operational contracts runtime, lifecycle state machines, and evidence verification |
| `cops/reporting/` | Offline engagement assessment joins and JSON/Markdown rendering |
| `cops/scenarios/` | Scenario and provenance registry loaders, queries, and cross-validation |
| `cops/capabilities/` | Capability reconciliation and truth-in-advertising auditor and matrix generator |
| `cops/routing/` | Deterministic artifact, BM25, and fuzzy routing, clarification, and proposed triad plans; optional bounded classifier callback |
| `cops/context.py`, `cops/preview.py` | Bounded local artifact discovery and previews without execution or authorization consumption |
| `cops/assessments/`, `cops/web_api/` | Bounded offline assessment and API inventory/replay runtimes |
| `cops/reports/` | SARIF, JUnit, and revision-bound Markdown export adapters |
| `cops/workflows/`, `catalog/workflows/` | Typed workflow compilation to ActionPlan, checkpointing, purple-team handoffs, pinned definitions and fixtures |
| `cops/laboratory/` | Disposable service exercises, isolation evidence, telemetry, and restoration checks |
| `cops/authorization.py` | Interactive operator authorization gate and cryptographic receipt validation |
| `cops/evidence/`, `cops/connectors/` | Opt-in evidence contracts and bounded acquisition SDK for repository tooling |
| `catalog/categories.json` | Stable capability taxonomy |
| `catalog/plugins.json` | Single canonical package inventory |
| `catalog/scenarios.json` | Canonical operational cybersecurity scenario registry |
| `catalog/provenance.json` | Pinned external research and tool provenance registry |
| `catalog/protocol-topics.json` | Pinned 70-topic protocol coverage and environment-limit inventory |
| `catalog/capabilities.json` | Reconciled four-mode capability truth-in-advertising registry |
| `catalog/schemas/package.schema.json` | Documented package governance contract |
| `catalog/schemas/specialist-profile.schema.json` | Specialist agent profile contract |
| `catalog/schemas/authorization-receipt.schema.json` | Tamper-evident authorization receipt contract |
| `catalog/schemas/evidence-envelope.schema.json`, `catalog/schemas/acquisition-receipt.schema.json` | Shared evidence and acquisition receipt v1 contracts |
| `catalog/schemas/assessment-input.schema.json`, `catalog/schemas/assessment-report.schema.json` | Offline assessment input and output contracts |
| `catalog/schemas/*-contract.schema.json`, `catalog/schemas/*-registry.schema.json` | Operational contracts, scenario, capability, and provenance registry schemas |
| `examples/evidence-sdk/` | Offline SDK walkthrough and design-only connector request plans |
| `plugins/<category>/<plugin-id>/` | Self-contained distributed product package |
| `plugins/<category>/<plugin-id>/playbooks/`, `walkthroughs/` | Validated machine-readable commands and corresponding operator guides included in portable exports |
| `plugins/logging-telemetry/security-logging-advisor/` | Repository scanning and security logging guidance |
| `plugins/detection-hunting/soc-investigation-workbench/` | Evidence-backed investigation planning and review |
| `plugins/detection-hunting/sentinel-hunt-workbench/` | Offline Sentinel hunt authoring, rendering, and stress evaluation |
| `plugins/detection-hunting/attack-path-workbench/` | Offline, evidence-linked analysis of illustrative attack paths |
| `plugins/offensive-security/attack-surface-planner/` | Approved-scope, offline attack-surface discovery and passive test planning |
| `plugins/offensive-security/host-assessment-workbench/` | Bounded Linux and Windows privilege-boundary import plus an opt-in read-only native Windows collector; no privilege crossing |
| `.agents/plugins/`, `.github/plugin/`, `.claude-plugin/` | Generated host marketplace indexes; do not edit manually |
| `AGENTS.md`, `.agents/skills/` | Canonical contributor contract and maintenance workflows |
| `.claude/skills/` | Generated contributor-skill mirrors; do not edit manually |
| `scripts/agent/`, `Makefile` | Contributor doctor, portable export, prerequisite installer, and full repository gate |
| `specs/`, `.specify/` | Product requirements, acceptance scenarios, and durable context |
| `tests/step_defs/` | Executable pytest-bdd acceptance steps |
| `docs/`, `docs/decisions/` | Operator guidance, architecture, governance, and decisions |
| `licenses/`, `THIRD_PARTY_NOTICES.md` | Project and imported-foundation attribution |

## Package ownership boundary

A package owns its v1.0.0 root `plugin.json`, Codex `.codex-plugin/plugin.json`, Claude
`.claude-plugin/plugin.json`, product skills, optional agents, scripts, examples,
schemas, package documentation, and deterministic tests. Shared code belongs at
the root only when multiple packages genuinely depend on one stable contract.
Cross-package use must name the dependency and fail closed when it is missing or
incompatible.

The host-neutral distribution is generated separately from each source package.
The export includes approved standard and namespaced files, and omits native host
manifests so Claude Code discovery remains available in the source marketplace.

The validator rejects unknown categories, incorrect category-first paths,
uncataloged packages, duplicate IDs or skill names, manifest/catalog divergence,
unsafe declared commands, unsupported evidence claims, and generated-index drift.

The `.agents/skills/plugin-run-cost/` contributor skill provides local retrospective
run accounting, input profiles, explicit forecasts and business comparisons. Its
synthetic fixtures are public; execution ledgers and customer source exports must
remain private outside the checkout. See the [skill](../.agents/skills/plugin-run-cost/SKILL.md).


`cops/assessments/network_inputs.py` interprets bounded typed firewall, Pod policy,
flow and DNS inputs for the shared artifact engine. It performs no discovery or
connectivity operations; execution adapters own active checks and authorization.
