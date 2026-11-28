# Compatibility & Evidence Boundaries

In defensive security, knowing the difference between what has been **verifiably tested** and what has merely been **assumed** is critical. A tool that produces a plausible report against mock test data might behave very differently when querying a live enterprise tenant with millions of events.

COPS is built around **honest evidence boundaries**. We clearly distinguish between what we prove in our automated local test suites and what requires human review, host installation, or live cloud credentials.

---

## 1. The Verification Matrix

Here is how each surface is tested in COPS, what our local tests prove, and what remains to be verified in your own environment:

| Surface | Repository Artifacts | What We Prove Locally | What You Verify in the Real World |
| :--- | :--- | :--- | :--- |
| **Host-Neutral CLI** | `python3 -m cops`, `package.json` | Catalog discovery, offline demos, parameter validation, and deterministic standard-library checks. | Command line ergonomics, shell aliases, and local terminal workflow integration. |
| **GitHub Copilot** | `plugin.json`, `.github/plugin/marketplace.json` | Manifest schema validity, tool declarations, package paths, and zero manifest drift against the master catalog. | Plugin installation in VS Code or Copilot CLI, GitHub authentication, and chat model activation. |
| **Claude Code** | `.claude-plugin/marketplace.json`, `.claude-plugin/plugin.json` | Manifest agreement with catalog, tool registration, agent definitions, and syntax checks. | Loading via `claude-code`, permission prompts, terminal streaming, and live hook execution. |
| **OpenAI Codex / ChatGPT** | `.agents/plugins/marketplace.json`, `.codex-plugin/plugin.json` | Manifest interface conformity, identity/version synchronization, and directory layout checks. | Runtime behavior in OpenAI workspace, prompt formatting, and context window limits. |
| **Universal Agent Plugins v1.0.0** | `dist/agent-plugins/`, `scripts/agent/export_portable.py` | Compliance with open Agent Plugins standard, path safety, clean exports without host-specific files. | Client-specific plugin loading, runtime sandboxing, and execution environments. |
| **Contributor Workflows** | `AGENTS.md`, `.agents/skills/`, `Makefile` | Repository rules, branch hygiene checks, automated adapter generation, and code quality linters. | AI assistant model nuances, agent reasoning depth, and task orchestration strategies. |
| **Live Cloud Services** (Sentinel, Azure, Wiz) | Connector scripts, hunting profiles, query templates | Query syntax correctness, parameter typing, synthetic fixture analysis, and offline graph modeling. | **Live cloud results**: Tenant IAM permissions, query execution latency, SIEM billing impact, real false-positive rates, and live data availability. |
| **Isolated Service Laboratories** | `cops/laboratory/`, synthetic datasets, service and workflow harnesses | Real HTTP/TLS interactions and telemetry can exercise authorization, revocation, detection and restoration. The readiness gate rejects an unverified isolation boundary. | Verify OS/container network isolation on the actual lab host, execute the complete required case set, and retain baseline restoration evidence. A localhost bind alone does not establish isolation. |

---

## 2. Understanding Our Support States

When reviewing COPS packages, documentation, and releases, you will encounter three explicit status labels:

- **`validated`**: The functionality has automated, executable evidence that passed directly in this repository (e.g., standard-library tests, schema validators, synthetic log parsers).
- **`unverified`**: The code, query templates, or manifests exist and are syntactically sound, but have not yet been executed against a live production tenant.
- **`not_applicable`**: The package intentionally does not support or require this integration (e.g., an offline planner designed specifically never to make network calls).

> [!NOTE]
> **Proof over Promises**:
> - Structural validation is not host execution.
> - Offline fixture testing is not live tenant verification.
> - Being listed in a marketplace index is not a guarantee of third-party store approval.

---

## 3. Distinct Scopes of Assurance

Record five separate scopes. Evidence in one scope does not establish another:

```mermaid
flowchart TD
    Evidence["Revision-bound evidence"]
    Evidence --> Structural["Structural validation"]
    Evidence --> Offline["Offline fixture execution"]
    Evidence --> Laboratory["Isolated lab activity and restoration"]
    Evidence --> Host["Installed-host smoke testing"]
    Evidence --> Live["Authorized live tenant validation"]
```

1. **Structural**: Ensures files are syntactically correct and comply with JSON schemas. Checked with `python3 -m cops validate`.
2. **Offline**: Runs algorithms against declared synthetic inputs. Checked with `python3 -m cops check <plugin-id>` and `python3 -m cops demo <plugin-id>`.
3. **Isolated laboratory**: Exercises actual service activity, telemetry correlation and cleanup inside an independently verified network boundary. Checked with `make check-laboratory`; required unavailable cases leave readiness incomplete.
4. **Host installation**: Loads the package into an AI assistant host and verifies discovery, skills and permissions.
5. **Live tenant integration**: Executes authorized queries or actions against the intended production integration. Requires deployment-specific scope, credentials and evidence. Package metadata alone cannot establish this state.

---

## 4. Host Smoke-Testing Checklist

Before certifying that a COPS plugin runs smoothly in your organization's specific AI assistant setup, follow this quick 5-step smoke test:

1. **Identify Host & Version**: Record the exact assistant name and release version (e.g., `Claude Code v1.0.12` or `GitHub Copilot CLI v0.2.1`).
2. **Clean Installation**: Install or register the plugin using documented discovery paths (e.g., pointing the assistant to the package directory).
3. **Verify Discovery**: Ask the assistant to list its available skills or tools. Confirm that the plugin's skills appear in the list.
4. **Execute Safe Offline Demo**: Prompt the assistant to run the plugin's safe offline demo or explain a packaged hunt. Ensure it requests only documented, expected permissions.
5. **Document the Evidence**: Record the date, assistant version, reviewer name, and observed output. Keep live-service claims separate unless real cloud telemetry was queried.

---

## 5. Authenticated Execution Compatibility and Migration

Authenticated execution adds an explicit compatibility check between the approved Action Plan and the selected worker. Operators provide the active Engagement, authorization trust store, and an independently provisioned, owner-only `cops.worker-capability-inventory/v1` artifact. That artifact identifies the worker and records exact tool versions, platform capabilities, measurement time, and measurement source. COPS does not populate that inventory through runtime host discovery; the worker owner is responsible for generating the measurement through a trusted host-baseline or deployment process and refreshing it when the host changes. At every external adapter launch, COPS separately locates the selected executable and verifies its operator-provisioned platform SHA-256 pin and adapter-declared upstream version before dispatch.

The loader requires the inventory to be a non-symlink regular file owned by the current user with no group or other permission bits. Before dispatch, the worker compares the signed snapshot with that inventory and rejects a tool-version or platform-capability mismatch, non-sequential batch semantics, an operation count above the signed maximum, or an optional expected-worker assertion that does not match the inventory.

External adapter execution is supported on Linux workers with an executable
`/proc/self/fd` mount. The version probe and operation launch use the same verified,
held staged inode; unsupported hosts, including macOS, fail closed. Built-in adapter
definitions require an operator-provisioned `--executable-sha256 TOOL=SHA256` value
for each installed platform binary. The general CLI, planning, and inventory
inspection remain portable; `inert` execution requires POSIX secure directory
descriptors. On non-POSIX hosts, the worker rejects even inert plans at workspace
preflight before authorization is consumed; the portable evidence reservation
helper is not wired into a complete worker lifecycle or cleanup path. Deploy the
worker under a dedicated UID:
descriptor-bound launch prevents pathname replacement but does not protect a staged
inode from a hostile process with the same UID.

Opening an older SQLite approval store preserves existing records but marks unsigned and digest-only approvals `legacy-untrusted`. The store exposes these through a separate read-only audit representation and retains their prior status as `historical_status`; they cannot authorize a new execution. Revalidate the current Engagement and plan, then issue a new authorization through an active trusted key; there is no automatic conversion or in-place trust upgrade.

Repository tests can prove deterministic contract validation, full-snapshot and worker binding, key/engagement window checks, compatibility rejection, atomic one-time consumption, legacy migration, bounded collection, and executable substitution rejection against local fixtures. Each deployment must still verify secret injection, file and database permissions, executable-pin provenance, the accuracy of the owner-provisioned capability measurement, same-UID isolation, operating-system process isolation, and live network controls on the actual worker host. See [Authenticated Execution](AUTHENTICATED_EXECUTION.md) for the operating procedure.

## 6. Expansion formats and runtime boundaries

Routing, artifact assessment, previews and report serialization use the portable
Python runtime. Optional classification is explicitly configured with a model,
deadline and budget and receives redacted features; unavailable classification
returns clarification. Cryptographic workflow bundle signing requires the declared
`cryptography` prerequisite and an independently trusted key. An unsigned bundle
does not become signed or trusted because its hashes match.

Cloud inputs are rendered Kubernetes/Helm manifests, Terraform **plan JSON** and
bounded configuration exports. Raw Terraform state and credentials are excluded
from discovery. Native forensic acquisition, EVTX parsing, container execution and
other heavy tools require registered, pinned adapters; unsupported formats return
limitations. Source and portable exports include playbooks, walkthroughs, fixtures
and the required vendored runtimes. See [artifact assessments](ARTIFACT_ASSESSMENTS.md),
[portable expansion](PORTABLE_EXPANSION.md) and
[migration](EXPANSION_MIGRATION.md) for the exact supported subsets.
