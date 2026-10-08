# COPS contributor skill guidance

Follow the canonical [root contract](../AGENTS.md). Author contributor skills in
`skills/`; keep entrypoints focused, with `name` and `description` frontmatter.
Offload data parsing, calculations, and deterministic checks to focused Python
scripts in `scripts/` so skills direct the agent to execute tools and reason over
compact outputs rather than processing raw bulk data in prompts.
Use relative paths and repository-owned commands. After changes, run
`make sync-agent-adapters` and `make check` from the repository root.

Product skills belong in `plugins/<category>/<plugin-id>/skills/`; they are distributed
with the plugin and are separate from these contributor workflows.

## Source contribution governance

When changing this repository, follow the root [AGENTS.md](../AGENTS.md):
checkpoint each substantial coherent change with operational commit messages,
update documentation and the threat model, and require independent human review
including affected existing code. Installed plugin execution does not gain Git
write or publishing authority from these source-contribution instructions.
