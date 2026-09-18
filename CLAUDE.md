# Claude Code Adapter

Read and follow `AGENTS.md` as the canonical repository contract. Use the generated
skills under `.claude/skills/`; their canonical sources live in `.agents/skills/`.

Do not edit generated skill copies directly. Run `make sync-agent-adapters` after
changing canonical skills and `make check-agent-adapters` to detect drift.

Claude-specific hooks and MCP configuration are optional and machine-sensitive.
Review `docs/HOOKS.md` and `docs/MCP.md` before enabling either.
