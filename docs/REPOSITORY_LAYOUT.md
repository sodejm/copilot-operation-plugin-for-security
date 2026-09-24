# COPS repository layout

| Path | Responsibility |
| --- | --- |
| `README.md`, `docs/GETTING_STARTED.md` | Analyst-first discovery and safe first use |
| `cops/` | Standard-library catalog, validation, command safety, demos, and checks |
| `catalog/categories.json` | Stable capability taxonomy |
| `catalog/plugins.json` | Single canonical package inventory |
| `catalog/schemas/package.schema.json` | Documented package governance contract |
| `plugins/<category>/<plugin-id>/` | Self-contained distributed product package |
| `plugins/logging-telemetry/security-logging-advisor/` | Repository scanning and security logging guidance |
| `plugins/detection-hunting/soc-investigation-workbench/` | Evidence-backed investigation planning and review |
| `plugins/detection-hunting/sentinel-hunt-workbench/` | Offline Sentinel hunt authoring, rendering, and stress evaluation |
| `.agents/plugins/`, `.github/plugin/`, `.claude-plugin/` | Generated host marketplace indexes; do not edit manually |
| `AGENTS.md`, `.agents/skills/` | Canonical contributor contract and maintenance workflows |
| `.claude/skills/` | Generated contributor-skill mirrors; do not edit manually |
| `scripts/agent/`, `Makefile` | Contributor doctor and full repository gate |
| `specs/`, `.specify/` | Product requirements, acceptance scenarios, and durable context |
| `tests/step_defs/` | Executable pytest-bdd acceptance steps |
| `docs/`, `docs/decisions/` | Operator guidance, architecture, governance, and decisions |
| `licenses/`, `THIRD_PARTY_NOTICES.md` | Project and imported-foundation attribution |

## Package ownership boundary

A package owns its Copilot `plugin.json`, Codex `.codex-plugin/plugin.json`, Claude
`.claude-plugin/plugin.json`, product skills, optional agents, scripts, examples,
schemas, package documentation, and deterministic tests. Shared code belongs at
the root only when multiple packages genuinely depend on one stable contract.
Cross-package use must name the dependency and fail closed when it is missing or
incompatible.

The validator rejects unknown categories, incorrect category-first paths,
uncataloged packages, duplicate IDs or skill names, manifest/catalog divergence,
unsafe declared commands, unsupported evidence claims, and generated-index drift.
