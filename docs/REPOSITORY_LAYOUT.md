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
| `security-logging-advisor/` | Distributed COPS Security Logging Advisor package |
| `security-logging-advisor/skills/` | Product scanning and recommendation skills |
| `soc-investigation-workbench/` | Local investigation planner, Codex plugin, two product skills, and guarded Sentinel vendoring |
| `.github/plugin/`, `.claude-plugin/` | Existing marketplace metadata |
| `specs/`, `.specify/` | Product requirements, Gherkin scenarios, project context |
| `tests/step_defs/` | Executable pytest-bdd scenarios |
| `docs/`, `docs/decisions/` | Contributor guidance and architectural decisions |
| `prompts/` | Optional milestone workflow prompts |
| `licenses/`, `THIRD_PARTY_NOTICES.md` | Imported foundation attribution |

This is a configured project, so PARK's generator scripts, license templates,
generator tests and template-only skill are not included. Canonical skill changes
flow one way through `make sync-agent-adapters`; `make check-agent-adapters`
detects drift. Root checks and plugin checks are combined by `make check`.
