# COPS contributor skill guidance

Follow the canonical [root contract](../AGENTS.md). Author contributor skills in
`skills/`; keep entrypoints focused, with `name` and `description` frontmatter.
Use relative paths and repository-owned commands. After changes, run
`make sync-agent-adapters` and `make check` from the repository root.

Product skills belong in `security-logging-advisor/skills/`; they are distributed
with the plugin and are separate from these contributor workflows.
