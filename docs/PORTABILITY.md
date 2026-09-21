# Portability architecture

COPS uses canonical, host-neutral package contracts and generates thin discovery
adapters for individual hosts.

```text
catalog/categories.json
catalog/plugins.json ─────────────── canonical inventory
          │
          ├── plugins/<category>/<id>/package.json
          │       ├── safe offline demo
          │       ├── deterministic validation
          │       ├── support evidence boundaries
          │       ├── plugin.json (GitHub Copilot)
          │       ├── .codex-plugin/plugin.json
          │       ├── .claude-plugin/plugin.json
          │       ├── skills/ + agents/ + scripts/
          │       └── package-specific adapters
          │
          ├── python3 -m cops ─────── operator interface
          │
          └── generated indexes
                  ├── .agents/plugins/marketplace.json
                  ├── .github/plugin/marketplace.json
                  └── .claude-plugin/marketplace.json
```

Repository maintenance has a separate canonical spine:

```text
AGENTS.md + .agents/skills/ + scripts/agent/ + Makefile
        ├── .github/copilot-instructions.md
        ├── CLAUDE.md + generated .claude/skills/
        └── .agents/rules/ + .agents/workflows/
```

## Portability rules

- Register a package once in `catalog/plugins.json`.
- Keep product code and instructions inside the package boundary.
- Keep Copilot, Codex, and Claude manifest identities aligned with the catalog;
  host-specific metadata stays explicit instead of being treated as interchangeable.
- Give every package a standard-library offline entry path.
- Invoke declared commands as argument arrays, never through a shell.
- Generate host indexes; do not maintain parallel inventories by hand.
- Treat adapters as pointers and metadata, not alternate workflow definitions.
- Make support claims independently for structure, offline behavior, host
  installation, and live integration.
- Use the same deterministic commands locally and in CI.

## What cannot be standardized completely

Hosts differ in packaging, discovery, account setup, permissions, hook events,
authentication storage, sandboxes, model selection, and orchestration. Live
security services also differ by tenant configuration and data availability. COPS
keeps these differences explicit instead of translating static files into support
claims.
