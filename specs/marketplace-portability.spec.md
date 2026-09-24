# Marketplace portability and factual reporting

## Purpose

Distribute cybersecurity plugins, agents, and skills from one catalog to GitHub
Copilot, Codex/ChatGPT, and Claude without overstating package capability or
delivery state.

## Package organization

- Every catalog entry has exactly one registered primary cybersecurity category.
- Every package lives at `plugins/<primary-category>/<plugin-id>`.
- Platform, vendor, runtime, and secondary concerns are tags, not additional
  primary categories.
- A new category is allowed only when no existing category describes the
  package's main security purpose and its distinction is documented in the
  category registry.

## Distribution

- Each package has an Agent Plugins v1.0.0 `plugin.json` at its root, using the
  pinned canonical schema and only standard manifest fields.
- Each package has a Codex manifest at `.codex-plugin/plugin.json`, including its
  required interface metadata.
- Each package has a Claude identity manifest at `.claude-plugin/plugin.json`.
- GitHub Copilot-specific agents and commands live under `com.github.copilot/`.
- The Codex, GitHub Copilot, and Claude marketplace indexes enumerate the same
  cataloged packages at their categorized paths.
- Host identity manifests and marketplace indexes retain native Claude Code and
  Codex discovery; the portable root skills are shared.
- A portable export includes the v1 core manifest, skills, required support files,
  and namespaced extension directories. It excludes source-only Claude, Codex,
  and legacy host directories while retaining the source package for Claude Code.
- New package-root entries must be classified as portable or source-only before
  export; unreviewed entries fail validation. An optional `mcp.json` is retained
  and checked against the v1 configuration contract.
- Each package declares tool prerequisites in
  `com.sodejm.copse/prerequisites.json`. Installation
  is a separate, explicit command and never runs during discovery or validation.
- Package descriptions state only capabilities present in the distributed
  package. Development-only or pending integrations remain explicit.

## Evidence contract

- Every finding separates the claim, classification, verification state,
  confidence, coverage, evidence, scope, limitations, conflicts, and uncertainty.
- Confidence uses plain-language states: `high`, `limited`, or `unknown`.
- Limited confidence, incomplete verification, partial coverage, stale evidence,
  unavailable evidence, or conflicts require a plain-language uncertainty
  statement.
- A verified, high-confidence finding requires complete coverage, current
  supporting evidence, no failed or unavailable evidence, and no conflicts.
- Delivery claims are separate typed states and require current evidence for the
  claimed state. A local validation cannot prove a commit, push, pull request,
  merge, release, or deployment.

## Acceptance criteria

- The marketplace validator rejects uncataloged paths, unknown categories,
  divergent marketplace indexes, missing host manifests, manifest identity drift,
  incomplete Codex interface metadata, invalid Agent Plugins v1.0.0 fields,
  and unsafe or malformed prerequisite declarations.
- The prerequisite command reports missing tools without changing the machine;
  install mode invokes a supported package manager only after an explicit flag,
  without a shell, and verifies the command afterward.
- The repository check runs all new code validation and prerequisite declaration
  checks, including success and rejection controls, and checks a clean portable
  export for every cataloged package. A new, unclassified root entry or unsafe MCP
  configuration fails the export gate.
- The finding validator accepts a fully supported finding.
- The finding validator rejects limited-confidence findings without uncertainty.
- The finding validator rejects high-confidence verified findings with stale,
  failed, or conflicting evidence.
- The finding validator rejects delivery states without state-specific evidence.
