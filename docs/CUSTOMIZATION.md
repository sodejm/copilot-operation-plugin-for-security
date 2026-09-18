# Customization

## Add project commands

Keep the stable targets `doctor`, `validate-contract`, and `check`. Extend `check`
with project-specific formatting, linting, type checking, tests, docs, security, and
generated-file validation. Agents should not need vendor-specific commands.

## Add nested instructions

Use a nested `AGENTS.md` only for a subtree with materially different commands or
constraints. State what it adds and rely on the root for everything else.

## Add a skill

Create `.agents/skills/<name>/SKILL.md`, validate it, then run:

```bash
make sync-agent-adapters
make check
```

## Add a vendor adapter

Keep it thin: point to the open spine, document discovery limitations, and add a
drift check if content must be copied. Do not place unique safety or delivery policy
only in an adapter.

## Add plugins or MCP servers

Document purpose, provenance, license, version, permissions, authentication, data
handling, supported clients, install/update/removal steps, and a safe fallback.
Prefer optional capabilities over making every contributor install an integration.
