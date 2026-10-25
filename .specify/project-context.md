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

## Bounded WebSocket replay

The Web API workbench's approved Python integration now includes a standard-library
RFC 6455 text subset. `cops/web_api/websocket.py` operates on an already pinned,
scope-checked socket and one deadline; it has no separate connector, approval
authority or shared session store. WebSocket version 1 operations bind exact
messages and frame/byte/time budgets, while HTTP version 2 operation digests stay
compatible. Package-local runtime synchronization includes the new module.
Mandatory local-service acceptance distinguishes completed protocol evidence from
partial/unknown outcomes. The CLI remains offline/preview-only. These controls
do not qualify OS/network isolation or production providers.

## Shared evidence SDK

`cops.evidence` and `cops.connectors` provide opt-in versioned evidence contracts,
finite acquisition budgets, exact-destination HTTPS, ephemeral authentication and
private transactional interruption recovery. Graph and Azure Resource Graph
fixtures exercise the shared lifecycle; other connector plans remain design-only.
Portable plugins must explicitly declare and distribute a compatible SDK before
adoption. See the [SDK specification](../specs/shared-evidence-sdk.spec.md) and
[guide](../docs/EVIDENCE_SDK.md) for raw/normalized evidence, security and migration.

## Local MCP authorization assessment

The `foundry-agent-harness` package binds a complete synthetic authorization
batch to one signed COPS Action Plan before starting its fixed peer and target
processes. The target evaluates its own principal, audience, tenant, tool scope,
delegation, expiry, revocation, and replay rules independently of COPS approval.
A private canary ledger records read disclosures and write effects separately
from peer requests and target decisions. Batch limits stop further admission and
cleanup is observed. Partial failures preserve completed evidence and usage, with
all snapshot failures and ordered recovery actions reported.

This is a POSIX local fixture with logical expiry and revocation. It does not
establish external provider interoperability, Windows execution, operating-system
egress enforcement, or durable endpoint orchestration. See the
[specification](../specs/agent-mcp-laboratories.spec.md) and
[package guide](../plugins/offensive-security/foundry-agent-harness/README.md).

## Model and effort advice

`cops.routing.model_advisor` classifies bounded tasks and ranks exact model/effort
pairs from a fresh operator-supplied catalog. It validates catalog shape,
availability, access, capabilities, tier, and supported effort, then emits
`cops.model-advice/v1` through both route CLIs. Catalog records are assertions;
the module does not probe providers, authenticate entitlement, dispatch work, or
change settings. The workbench plugin exports the skill and guide while command
execution requires a COPS checkout. See the
[specification](../specs/model-effort-routing.spec.md) and
[operator guide](../docs/model-effort-routing.md).

## Assessment budget fixture

`cops.assessment_budget` is an opt-in, engagement-scoped SQLite admission ledger
with a synthetic dispatcher. It atomically charges child attempts and retries,
keeps uncertain dispatches reserved across cancellation and restart, signals
active fixture callbacks on cancellation, and binds the operator's price
assumptions to the policy. The provider gateway emulator assessment reserves
each dispatch before sending it and retains uncertain attempts. The
current ledger does not establish provider billing or authorize a paid call.
See the [budget specification](../specs/aggregate-assessment-budgets.spec.md)
and [operator guide](../docs/ASSESSMENT_BUDGETS.md).

## Authenticated execution boundary

High-consequence execution requires an authorization signed over the complete
immutable Action Plan snapshot and the expected worker identity. A separate approval
authority holds verifier trust, the active Engagement, and the protected approval
store. The worker presents only the authorization identifier and exact plan through a
local control channel bound to its process credentials and worker identity. The
worker checks the plan against an owner-provisioned
`cops.worker-capability-inventory/v1` measurement artifact, checks Linux sandbox
readiness, and asks the authority to verify and atomically consume the authorization
before dispatch. The inventory records worker identity, exact tool
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
Remote requests use bounded, versioned JSON over SSH with a pinned host key and exact
host and worker identities. The Linux worker requires process sandbox controls for
namespaces, file descriptors, environment, privileges, resources, and output; absent
controls fail closed before approval consumption. Deployments must still provision
separate accounts and protected local paths and verify those host controls in place.
The deployed worker operation path does not yet route provider requests through
an operator gateway. A gateway still requires exact-revision worker, gateway,
identity, isolation, and credential evidence. The worker must run under a
dedicated UID because a hostile same-UID process can still interfere with
worker-owned state.

Remote isolated-worker calls use `cops.remote-worker/v1`: one bounded JSON request
and response over an absolute OpenSSH client configured with one privately staged,
exact known-host pin. SSH configuration, proxies, forwarding, and local commands
are disabled. The response must exactly bind the request identifier, configured
host, and expected worker identity before its payload is returned. This transport
binding does not replace worker-side approval consumption, sandboxing, or egress
mediation.

## Evidence policy

Local pre-push validation pins a reviewed policy and validates the proposed commit
in an isolated checkout. It checks the whole feature branch for meaningful test
updates and blocks scanner or canonical-check failures. The checkout excludes
private untracked inputs but executes repository code with developer permissions;
it is not an OS sandbox. Hooks remain bypassable and do not replace CI. See the
[specification](../specs/local-push-gate.spec.md) and
[installation guide](../docs/LOCAL_PUSH_GATE.md).

Static structure, offline behavior, host installation, and live service behavior
are separate claims. A manifest, generated index, fixture, or local passing test
cannot promote host or live state. Stronger states require a dated, reproducible,
reviewed evidence record under a repository-defined contract.

See [Getting Started](../docs/GETTING_STARTED.md),
[architecture](../ARCHITECTURE.md), [repository layout](../docs/REPOSITORY_LAYOUT.md),
and [adding a plugin](../docs/ADDING_A_PLUGIN.md).

## Optional artifact parsers

The operator core remains standard-library based. Binary Sysmon EVTX import uses
the fixed `sysmon-evtx/v1` adapter with `python-evtx==0.8.1` and `hexdump==3.3`
in a resource-limited Linux subprocess. It validates a read-only snapshot before
normalizing supported records; native acquisition is a separate capability.
See [the import specification](../specs/evtx-import.spec.md).

Raw disk/memory imports use the registered POSIX `raw-forensic-image/v1`
adapter, strict versioned metadata, bounded streaming and shared no-follow file
helpers. Integrity, asserted provenance and unperformed analysis remain separate.
See `specs/forensic-import.spec.md` and the forensic service-laboratory case.

Kubernetes containment acceptance uses `isolated-k3s-containment/v1` on a
disposable privileged K3s node, separate from the unprivileged service container.
Both adapters require observed isolation, activity, telemetry and restoration.
The composite gate requires twelve service cases plus real Kubernetes enforcement;
see `docs/KUBERNETES_LABORATORY.md` for pinned prerequisites and host limitations.

Integrated CVE playback shares exact component/advisory binding with the service
laboratory. Real query invocation records distinguish affected and fixed source
identities; missing or unrelated evidence remains insufficient. This is a pinned
synthetic advisory case, with no general non-exploitability or provider claim.

Consent remediation now requires tenant-bound grant, service-principal and sign-in
exports with explicit completeness and observation windows. Offline correlation
returns targets only for exact identity joins. Isolated acceptance must revoke
the selected synthetic grant while preserving an unrelated grant; production
Entra and session/hunt operations remain unverified.

Exposure playback requires complete, in-window DNS, connection and authentication
evidence for each exact endpoint. Its isolated lab observes a fixed non-forwarding
DNS answer plus actual vulnerable/corrected HTTP responses. Incomplete coverage
and DNS failures cannot clear an audit; production discovery remains unverified.

Supply-chain laboratory acceptance uses a registered offline installer for two
reviewed synthetic wheels. Actual installed-code HTTP behavior, source hashes,
tamper rejection and cleanup augment the artifact assessor. The strict gate
requires its pinned installer; arbitrary packages and registry execution remain
unsupported. See `docs/SERVICE_LABORATORY.md` for prerequisites and evidence limits.
