# Specification: Portable operator workflow

## Purpose

The repository provides a single, catalog-driven operator entry point for every
cybersecurity package. A new analyst can discover capabilities, see evidence
boundaries, and run one safe offline example without knowing package-specific
commands. A contributor can validate the same package contracts and regenerate
host indexes from the canonical catalog.

## Acceptance criteria

1. `python3 -m cops doctor` verifies the local runtime and repository contract
   without downloading dependencies or contacting a service.
2. `python3 -m cops list` shows every cataloged package and independently reports
   offline workflow, host installation, and live integration support.
3. `python3 -m cops demo <plugin-id>` runs only the package-owned command declared
   in `package.json`, without a shell and with a bounded timeout.
4. `python3 -m cops check [plugin-id ...]` runs the deterministic checks declared
   by the selected package or every package when no ID is supplied.
5. Package commands using absolute paths, parent traversal, non-Python entry
   points, or files outside the package fail before execution.
6. `.agents/plugins/marketplace.json`, `.github/plugin/marketplace.json`, and
   `.claude-plugin/marketplace.json` are generated from `catalog/plugins.json` and
   drift causes validation to fail.
7. Every package has distinct Copilot, Codex, and Claude manifests whose ID and
   version match the canonical catalog; the Codex manifest also declares its
   required user-facing interface metadata.
8. Structural, offline, host-installation, and live-integration evidence remain
   separate. Repository checks never promote host or live support automatically.
9. The operator commands run on Python 3.11 or newer on Linux, macOS, and Windows.
