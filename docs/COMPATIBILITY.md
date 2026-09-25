# Compatibility and evidence boundaries

COPS separates repository portability from product-specific installation claims.
The root CLI and package checks are the portable baseline; host indexes are derived
discovery metadata.

| Surface | Repository artifact | What is validated here | What remains separate |
| --- | --- | --- | --- |
| Host-neutral operation | `python3 -m cops`, `package.json` | Catalog discovery, safe command constraints, offline demos, deterministic package checks | Assistant activation, UI behavior, permissions, credentials |
| Codex discovery | package `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json` | Manifest interface, identity/version agreement, package location, generated-index drift | Installation in a specific Codex version and runtime behavior |
| Agent Plugins v1.0.0 export | package `plugin.json`, `skills/`, namespaced extensions, `export_portable.py` | Closed root manifest, skill structure, prerequisite declaration, export content and path safety | Installation and execution in a specific client |
| GitHub Copilot discovery | package `plugin.json`, `.github/plugin/marketplace.json` | Manifest schema and identity, catalog-derived index shape, package location | Supported client surfaces, installation, authentication, execution |
| Claude discovery | `.claude-plugin/marketplace.json`, package `.claude-plugin/plugin.json` | Catalog-derived index and manifest identity | Installation, permissions, hooks, and execution in a specific version |
| Contributor agents | `AGENTS.md`, `.agents/skills/`, generated `.claude/skills/` | Contract and adapter drift checks | Model behavior and proprietary orchestration |
| Live security services | package-specific connectors or procedures | Nothing unless a dedicated evidence record says otherwise | Tenant schema, role access, query results, latency, cost, safety, false positives |

## Support-state meanings

- `validated`: the named scope has executable evidence in this repository.
- `unverified`: artifacts may exist, but the repository has no accepted evidence
  proving the named scope.
- `not_applicable`: the package intentionally has no such integration.

Structural validation is not host validation. Offline fixture execution is not
live integration validation. Generated marketplace membership is not installation.

The repository source packages retain `.claude-plugin/` and `.codex-plugin/`
manifests for native discovery. Those host manifests are omitted from the v1.0.0
portable export. Optional `agents/` definitions may be included for Claude Code;
they are outside the two portable v1.0.0 component types and other clients can
ignore them. Run `python3 scripts/agent/export_portable.py --check` to verify
the exported packages, or use `--output dist/agent-plugins` to create them.
Tool prerequisites are data-only declarations under `com.sodejm.copse/`.
`install_prerequisites.py --check` is read-only; `--dry-run` previews package
manager commands; `--install` runs them only when explicitly requested.

## Host smoke-test acceptance criteria

Before recording a host as validated, a reviewer must be able to reproduce a clean
test that:

1. names the host and exact version;
2. installs or loads the package from its documented source;
3. discovers the expected skill or command;
4. runs a non-destructive example with only documented permissions;
5. captures expected and observed results plus date and reviewer;
6. keeps live-service proof separate unless the service was actually exercised.

Support changes over time, so verify current official host documentation before
relying on discovery paths, permissions, hooks, or authentication behavior.
