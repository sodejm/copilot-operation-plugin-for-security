# Claude Code Adapter

Read and follow `AGENTS.md` as the canonical repository contract. Use the generated
skills under `.claude/skills/`; their canonical sources live in `.agents/skills/`.

Do not edit generated skill copies directly. Run `make sync-agent-adapters` after
changing canonical skills and `make check-agent-adapters` to detect drift.

Claude-specific hooks and MCP configuration are optional and machine-sensitive.
Review `docs/HOOKS.md` and `docs/MCP.md` before enabling either.

<!-- squad:begin (managed by Squad; do not edit between markers) -->
## Squad

This project uses Squad. Run `claude --agent squad --mcp-config .mcp.json` (interactive Claude Code does not load project-scoped `.mcp.json` servers until approved, so pass the config explicitly; or delegate to the `squad` subagent) to work with the team defined in `.squad/team.md`. Shared state is served by the `squad_state` MCP server in `.mcp.json`.
<!-- squad:end -->

## Automatic Squad routing

For implementation work, follow the automatic Squad orchestration section of
`AGENTS.md` and `docs/SQUAD.md`; load the roster and route independent work
automatically. Root policy takes precedence over generated Squad defaults.
