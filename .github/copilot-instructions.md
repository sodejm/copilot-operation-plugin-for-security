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
