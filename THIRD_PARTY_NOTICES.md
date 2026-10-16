# COPS third-party notices

## Portable Agent Repository Kit (PARK)

- Source: https://github.com/sodejm/portable-agent-repository-kit
- Revision: `bfc41923fb497b495e95dc7dee644313b51b368b`
- License: [Apache License 2.0](licenses/PARK-Apache-2.0.txt)
- Adoption date: 2026-09-16

Imported foundation: root contributor/governance/agent contracts, Makefile,
editor/Git/pre-commit examples, Codex and MCP examples, GitHub issue/PR templates,
CODEOWNERS, Dependabot and repository-contract workflow; `.agents/rules/`,
`.agents/workflows/`, `prompts/`, `scripts/agent/`, `scripts/_template_common.py`,
and baseline contributor documentation under `docs/`.

Imported canonical skills: `agent-workboard`, `documentation-impact`,
`github-state-audit`, `gitignore-audit`, `milestone-delivery`, `repository-check`,
`repository-delivery-gate`, `repository-orientation`, `resumable-worktree-run`,
`security-review`, and `session-usage-audit`, including their supporting resources.
Generated `.claude/skills/` copies retain the provenance of their canonical source.
The four pre-existing COPS contributor skills retain the project's original terms.

COPS modifications include project branding and contributor guidance, integration
of plugin and BDD tests into the check runner, source enumeration that respects
Git ignores and excludes symlinks, environment diagnostics, and CI test setup.
These modifications are documented here and in the root changelog. No upstream
NOTICE file was present at the recorded revision. The existing project LICENSE
is preserved separately and does not replace the imported Apache license.

## OASIS SARIF 2.1.0 schema

- Source: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json>
- Standard: SARIF Version 2.1.0, OASIS Standard, 27 March 2020
- Notices: [OASIS copyright and permissions](licenses/OASIS-SARIF-2.1.0-NOTICE.txt)
- Retrieval date: 2026-10-15
- SHA-256: `ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25`

The unmodified schema at `cops/reports/schemas/sarif-schema-2.1.0.json` is used
for mandatory offline report conformance tests. The accompanying notice retains
the standard's full Notices section. COPS's project license does not replace
these terms.
