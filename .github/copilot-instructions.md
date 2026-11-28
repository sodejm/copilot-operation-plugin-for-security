# GitHub Copilot Adapter

`AGENTS.md` is this repository's canonical instruction contract. Follow it before
making changes. Reusable task workflows live under `.agents/skills/`.

Use repository-owned commands, especially `make doctor` and `make check`. Preserve
unrelated changes, keep validation claims evidence-based, and do not perform remote
or release actions without explicit authorization.

## Automatic Squad routing

For implementation work, follow the automatic Squad orchestration section of
`AGENTS.md` and `docs/SQUAD.md`; load the roster and route independent work
automatically. Root policy takes precedence over generated Squad defaults.

## Detection Quality requests

When an operator asks to review the bundled detection fixtures, send the original ask to `cops/request`. On acceptance, continue with its run ID in the same turn. Report the run ID, case counts, gaps by platform, and which suites were evaluated or reused.

When asked to resume, use the matching run ID in this chat. If several runs match, ask which one. If the ID is missing, ask for the saved ID. Start a fresh review only when the operator requests one. The optional COPS agent uses the same tool.
