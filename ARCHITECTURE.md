# COPS architecture

COPS is a catalog-driven collection of self-contained cybersecurity packages. It
separates product capabilities from repository-maintenance workflows and separates
offline evidence from host and live-service claims.

```mermaid
flowchart TD
    A[catalog/plugins.json] --> B[Package governance contract]
    B --> C[Skills, agents, scripts, examples]
    B --> D[Safe offline demo]
    B --> E[Deterministic checks]
    A --> F[python3 -m cops]
    A --> G[Generated Codex index]
    A --> H[Generated Copilot index]
    A --> I[Generated Claude index]
    J[AGENTS.md and contributor skills] --> K[Repository check]
    D --> K
    E --> K
    G --> K
    H --> K
    I --> K
```

## Canonical contracts

`catalog/plugins.json` owns package identity, version, category, location, and
tags. Each package's `package.json` owns maturity, limitations, evidence states,
safe demo, and validation commands. The `cops` module validates both, constrains
command execution to package-owned Python scripts with timeouts and no shell, and
generates all host marketplace indexes. Each package keeps distinct Copilot,
Codex, and Claude manifests because their metadata contracts are not
interchangeable.

Product assets remain under `plugins/<category>/<plugin-id>/`. This category-first
layout keeps a growing catalog browsable while preserving each package as a unit
that can be reviewed or distributed independently.

## Included product boundaries

- Security Logging Advisor collects local repository signals and guides reviewed
  logging recommendations.
- SOC Investigation Workbench plans bounded investigations from analyst-supplied,
  redacted evidence; it does not execute queries or response actions.
- Sentinel Hunt Workbench owns hunt content, profiles, rendering, deterministic
  reference evaluation, and generated platform adapters. Its offline suite does not
  emulate Kusto or prove Microsoft Sentinel tenant behavior.
- Attack Path Workbench analyzes illustrative local exports and keeps conditional
  path claims linked to their source evidence.
- Attack Surface Planner validates approval and scope against pinned local exports,
  then produces passive hypotheses and a test plan. It cannot execute active tests
  or authorize targets discovered in those exports.

SOC-to-Sentinel handoff remains a guarded cross-package integration. The existence
of both packages does not by itself validate the handoff or a live query path.

## Shared evidence acquisition

`cops.evidence` owns the versioned envelope and acquisition receipt schemas under
`catalog/schemas/`, canonical hashes, validation and provider-independent
completeness/freshness assessment. `cops.connectors` owns finite acquisition bounds,
ephemeral authentication, fixed-route HTTPS and private transactional checkpoints.
Reviewed adapters project source responses before this shared lifecycle persists
evidence. Graph and Azure Resource Graph examples exercise it offline.

Normalized envelopes and receipts are separate records joined by acquisition ID,
tenant, scope and request fingerprint. Raw data, if authorized, belongs in a
separate caller-owned store; envelopes carry only opaque references and hashes.
Query completion does not establish source coverage or consistency.

This root SDK is an opt-in repository dependency and is not included automatically
in self-contained portable plugin exports. Existing plugin formats retain their
contracts. See the [SDK guide](docs/EVIDENCE_SDK.md) for adapter authoring, storage,
versioning and rollback boundaries.

## Contributor architecture

`AGENTS.md`, `.agents/skills/`, `scripts/agent/`, and the `Makefile` own repository
maintenance. Generated `.claude/skills/` and thin instruction adapters point back
to that canonical policy. Specifications and pytest-bdd scenarios define
observable acceptance criteria. The complete gate combines repository contracts,
adapter drift, package checks, and behavior tests.

See [Getting Started](docs/GETTING_STARTED.md),
[Repository Layout](docs/REPOSITORY_LAYOUT.md), and
[Adding a Plugin](docs/ADDING_A_PLUGIN.md).
