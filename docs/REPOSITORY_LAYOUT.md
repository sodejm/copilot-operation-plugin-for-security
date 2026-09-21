# COPS repository layout

| Path | Responsibility |
| --- | --- |
| `AGENTS.md` | Canonical contributor contract |
| `CLAUDE.md`, `.github/copilot-instructions.md` | Thin environment adapters |
| `.agents/skills/` | Canonical portable contributor skills and COPS-specific workflows |
| `.claude/skills/` | Generated contributor skill mirrors; do not edit directly |
| `.agents/rules/`, `.agents/workflows/` | Portable rule and workflow adapters |
| `scripts/agent/` | Doctor, contract validation, adapter synchronization, full check |
| `scripts/_template_common.py` | Retained PARK helper used for adapter generation |
| `catalog/` | Canonical categories, package records, finding schema, and validation examples |
| `plugins/<category>/<plugin-id>/` | Distributed plugin packages grouped by their primary cybersecurity function |
| `plugins/logging-telemetry/security-logging-advisor/` | Security logging advisor package |
| `plugins/detection-hunting/soc-investigation-workbench/` | Local investigation planner, two product skills, and guarded Sentinel vendoring |
| `.agents/plugins/`, `.github/plugin/`, `.claude-plugin/` | Host marketplace indexes kept in sync with the canonical catalog |
| `specs/`, `.specify/` | Product requirements, Gherkin scenarios, project context |
| `tests/step_defs/` | Executable pytest-bdd scenarios |
| `docs/`, `docs/decisions/` | Contributor guidance and architectural decisions |
| `prompts/` | Optional milestone workflow prompts |
| `licenses/`, `THIRD_PARTY_NOTICES.md` | Imported foundation attribution |

This is a configured project, so PARK's generator scripts, license templates,
generator tests and template-only skill are not included. Canonical skill changes
flow one way through `make sync-agent-adapters`; `make check-agent-adapters`
detects drift. The marketplace validator rejects unknown categories, misplaced or
uncataloged packages, divergent host indexes, invalid manifests, and unsupported
finding claims. Root checks and plugin checks are combined by `make check`.
