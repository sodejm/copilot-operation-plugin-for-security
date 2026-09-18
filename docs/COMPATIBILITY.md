# Compatibility

| Capability | Codex | Copilot | Claude Code | Antigravity | ChatGPT |
| --- | --- | --- | --- | --- | --- |
| Root contract | Native `AGENTS.md` | Adapter points to `AGENTS.md` | `CLAUDE.md` points to `AGENTS.md` | `AGENTS.md` plus rule adapter | Provide through linked project/context |
| Agent Skills | `.agents/skills/` | Supported surfaces may discover `.agents/skills/` | generated `.claude/skills/` | `.agents/skills/` | Requires a custom integration |
| MCP | Client config | Surface-dependent | `.mcp.json` or user config | Surface-dependent | Custom MCP/App integration |
| Hooks | Product/global mechanisms | GitHub workflows and product controls | `.claude/settings*.json` | workspace workflows/rules | Automation outside ordinary chat |
| CI evidence | GitHub Actions | GitHub Actions | GitHub Actions | GitHub Actions | Linked GitHub context |

Support changes over time. Verify current product documentation before relying on
a particular discovery path, permission, or hook. The portable fallback is always
to tell the environment to read `AGENTS.md`, select a relevant canonical skill,
and run the repository-owned command.

## Compatibility test

For each supported environment, verify that a fresh session can:

1. identify `AGENTS.md` as authoritative;
2. discover or be directed to one relevant skill;
3. run `make doctor` and `make check` with normal approvals;
4. explain that remote writes need explicit authorization;
5. report local and hosted evidence as distinct states.

Record version-specific exceptions in the project, not in global machine policy.
