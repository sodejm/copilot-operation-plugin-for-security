# COPS project context

**COPS (Copilot Operations Plugins for Security)** is a catalog-driven project for
portable cybersecurity plugins, agents, skills, and deterministic local tools.
Product packages use the category-first path `plugins/<category>/<plugin-id>/`.
The current catalog contains Security Logging Advisor, SOC Investigation Workbench,
Sentinel Hunt Workbench, Attack Path Workbench, and Attack Surface Planner.

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
- Attack Path Workbench analyzes illustrative local exports and records conditional,
  evidence-linked paths without contacting a live graph provider.
- Attack Surface Planner checks an approved scope manifest and four pinned local
  export types before producing passive hypotheses and a test plan. It performs no
  tenant, DNS, or endpoint requests, and a discovery finding does not grant
  authorization for active testing.

SOC-to-Sentinel handoff is an explicit, guarded integration boundary. Co-location
in this repository does not establish compatibility or release readiness. Package
validation must continue to fail closed when required version or integrity evidence
is absent.

## Shared evidence SDK

`cops.evidence` and `cops.connectors` provide opt-in versioned evidence contracts,
finite acquisition budgets, exact-destination HTTPS, ephemeral authentication and
private transactional interruption recovery. Graph and Azure Resource Graph
fixtures exercise the shared lifecycle; other connector plans remain design-only.
Portable plugins must explicitly declare and distribute a compatible SDK before
adoption. See the [SDK specification](../specs/shared-evidence-sdk.spec.md) and
[guide](../docs/EVIDENCE_SDK.md) for raw/normalized evidence, security and migration.

## Authenticated execution boundary

High-consequence execution requires an authorization signed over the complete
immutable Action Plan snapshot and the expected worker identity. The worker verifies
that authorization through an independently supplied trust store and active
Engagement, checks the plan against an owner-provisioned
`cops.worker-capability-inventory/v1` measurement artifact, and atomically consumes
the authorization before dispatch. The inventory records worker identity, exact tool
versions, platform capabilities, measurement time, and measurement source. It is a
trusted provisioning input; COPS does not populate it through runtime host discovery.
For each external adapter launch, the worker separately verifies an
operator-provisioned platform SHA-256 and the adapter's pinned upstream executable
revision. Linux launches bind the version probe and operation to the same held staged
inode through `/proc/self/fd`; unsupported platforms fail closed. Raw stdout and
stderr are bounded during collection. A timeout or raw-output overflow suppresses
all retained bytes before redaction and persistence. The worker reserves a unique
evidence inode before dispatch, revalidates it before a directory-relative
non-following write, and reports post-redaction truncation as a partial result.

HMAC authenticates membership in the shared-key verifier channel and does not provide
non-repudiation because every key holder can mint an authorization. Existing unsigned
or digest-only approval rows migrate to `legacy-untrusted` and cannot execute.
Operating-system and process transport isolation (issue #185) and live network egress
mediation (issue #186) remain deployment controls outside this authorization proof.
The worker must run under a dedicated UID because a hostile same-UID process can
still modify a staged inode or interfere with held descriptors.

## Evidence policy

Static structure, offline behavior, host installation, and live service behavior
are separate claims. A manifest, generated index, fixture, or local passing test
cannot promote host or live state. Stronger states require a dated, reproducible,
reviewed evidence record under a repository-defined contract.

See [Getting Started](../docs/GETTING_STARTED.md),
[architecture](../ARCHITECTURE.md), [repository layout](../docs/REPOSITORY_LAYOUT.md),
and [adding a plugin](../docs/ADDING_A_PLUGIN.md).
