# COPS project context

**COPS (Copilot Operations Plugins for Security)** is a catalog-driven project for
portable cybersecurity plugins, agents, skills, and deterministic local tools.
Product packages use the category-first path `plugins/<category>/<plugin-id>/`.
The current catalog contains Security Logging Advisor, SOC Investigation Workbench,
and Sentinel Hunt Workbench.

Python 3.11+ implements the host-neutral `python3 -m cops` operator interface,
local tools, and package validation. Markdown holds instructions and durable
evidence boundaries; JSON holds catalogs, manifests, package contracts, schemas,
fixtures, and examples. The operator path uses only the standard library. Pytest
and pytest-bdd are contributor dependencies for executable acceptance scenarios.

`catalog/plugins.json` is the canonical inventory. Each package has a `package.json`
governance contract, root `plugin.json`, `.claude-plugin/plugin.json`, at least one
canonical product skill, a safe demo, deterministic checks, and explicit structural,
offline, host-installation, and live-integration states. Root-generated marketplace
indexes must never become independent sources of truth.

PARK-derived contributor workflows live under `.agents/`, with generated
`.claude/skills/` copies. Root `AGENTS.md` is canonical across environments.
`make check` combines repository and package contracts, adapter drift checks,
package-declared validation, tests, and BDD scenarios. GitHub Actions also runs a
dependency-free operator smoke test on Linux, macOS, and Windows.

## Package boundaries

- Security Logging Advisor scans local repository signals and supports reviewed,
  cost-aware security logging recommendations. It does not prove security or
  compliance, and host installation remains unverified.
- SOC Investigation Workbench validates analyst-supplied redacted cases, explicit
  evidence associations, hypothesis branches, question dependencies, budgets, and
  review reports. It does not execute queries or response actions.
- Sentinel Hunt Workbench owns 12 gold hunt definitions, profiles, renderers,
  deterministic curated and adversarial reference tests, and generated platform
  adapters. Its evaluator is not Kusto or Microsoft Sentinel; tenant behavior,
  cost, latency, false positives, host activation, and live integration remain
  unverified.

SOC-to-Sentinel handoff is an explicit, guarded integration boundary. Co-location
in this repository does not establish compatibility or release readiness. Package
validation must continue to fail closed when required version or integrity evidence
is absent.

## Evidence policy

Static structure, offline behavior, host installation, and live service behavior
are separate claims. A manifest, generated index, fixture, or local passing test
cannot promote host or live state. Stronger states require a dated, reproducible,
reviewed evidence record under a repository-defined contract.

See [Getting Started](../docs/GETTING_STARTED.md),
[architecture](../ARCHITECTURE.md), [repository layout](../docs/REPOSITORY_LAYOUT.md),
and [adding a plugin](../docs/ADDING_A_PLUGIN.md).
