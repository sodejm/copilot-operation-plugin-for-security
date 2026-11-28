# Marketplace package contract

- Choose exactly one primary category from `catalog/categories.json` before
  adding a package, and place it at `plugins/<primary-category>/<plugin-id>`.
- Treat platforms, vendors, runtimes, and secondary concerns as tags. Add a
  category only when no registered category describes the package's main
  security purpose, and document the distinction in the registry.
- Keep `catalog/plugins.json` and every host marketplace index synchronized.
- Report only what available evidence supports. Separate observations,
  assessments, and unresolved questions. Never invent evidence, imply an
  unperformed check passed, or describe attempted work as completed.
- State missing evidence, limited coverage, and uncertainty in plain language.
  Narrow a claim when the evidence cannot establish the broader claim.
- Keep local validation, commit, push, pull request, merge, release, and
  deployment as distinct delivery states.

## Source contribution governance

When changing this repository, follow the root [AGENTS.md](../AGENTS.md):
checkpoint each substantial coherent change with operational commit messages,
update documentation and the threat model, and require independent human review
including affected existing code. Installed plugin execution does not gain Git
write or publishing authority from these source-contribution instructions.
