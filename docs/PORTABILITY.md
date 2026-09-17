# Portability architecture

COPS uses one open spine with small environment adapters.

```text
AGENTS.md                    canonical instructions
.agents/skills/              canonical reusable workflows
scripts/agent/ + Makefile    deterministic repository checks
docs/                        durable context and decisions
MCP                          portable external tool protocol
        |
        +-- .github/copilot-instructions.md
        +-- CLAUDE.md + generated .claude/skills/
        +-- .agents/rules/ and .agents/workflows/
        +-- .codex/config.toml.example
```

## Standards-first decisions

- Use `AGENTS.md` for repository instructions. Nested contracts are allowed for
  genuinely different subtrees.
- Author skills in `.agents/skills/<name>/SKILL.md` with YAML frontmatter containing
  `name` and `description`.
- Use MCP for reusable tool servers rather than embedding vendor-specific tool APIs
  in repository instructions.
- Expose stable repository commands. Agents and humans should run the same checks.
- Treat CI as enforcement and hooks as optional local acceleration.

## Adapter rule

An adapter may tell an environment where the canonical source is and provide
environment-specific discovery metadata. It must not redefine workflow policy.
COPS checks generated Claude skill copies for drift.

## What cannot be standardized completely

- plugin packaging, installation, accounts, and permissions;
- hook lifecycle events and configuration syntax;
- automatic repository context discovery in ordinary ChatGPT conversations;
- MCP client configuration and authentication storage;
- sandbox, network, browser, terminal, and hosted-service authority;
- model selection, subagent behavior, and proprietary orchestration.

COPS documents these boundaries rather than pretending they do not exist.
