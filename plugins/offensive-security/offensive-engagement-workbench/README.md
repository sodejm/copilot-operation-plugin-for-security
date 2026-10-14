# COPS Offensive Engagement Workbench

`offensive-engagement-workbench` provides authorized adversarial assessment intake, scope boundary validation, execution mode classification, and reviewable immutable action planning for the Copilot Operations Plugin for Security (COPS) ecosystem.

Use the [deterministic playback guide](docs/PLAYBOOK.md) for the runnable offline
demonstration. Follow the [end-to-end verification guide](docs/VERIFICATION.md)
for the broader package qualification workflow.

## Deterministic planning playback

From the repository root, run:

```bash
python3 -m cops demo offensive-engagement-workbench
```

The manifest command writes six artifacts under
`build/playbacks/offensive-engagement-workbench` and prints this completion
record:

```json
{
  "engagement_id": "eng-synthetic-e03",
  "mode": "planning",
  "network_requests": 0,
  "operations_count": 1,
  "status": "passed",
  "target": "10.100.0.10"
}
```

The playback validates the synthetic engagement, compiles one draft action,
proposes an approval-pending specialist handoff, and sends a small plan summary
to a local isolated Python subprocess. The child only echoes a structured
observation; it has no network code and does not execute the planned operation.
The parent accepts success only after checking the complete observation and
hashing the child's raw stdout and stderr. This exercises the package boundary
without claiming authorization, target reachability, worker readiness, or a
live assessment result.

### Design rationale and data flow

The workflow separates planning contracts from process evidence so each
boundary can be checked independently. Validated intake feeds an immutable
draft plan; the repository handoff router produces a pending proposal; a local
isolated child observes only a compact plan summary; and the parent validates
and hashes the raw process output before writing the completion marker.

```text
fixture -> validated engagement -> draft action plan -> proposed handoff
                                      |
                                      v
                              local inert child
                                      |
                                      v
                       semantic checks + hashes -> result
```

| Artifact | Purpose | Producer | Consumer | Validation |
| --- | --- | --- | --- | --- |
| `engagement.json` | Preserve normalized planning scope. | Intake validator | Action-plan builder and operator | Valid contract with mode `planning`. |
| `action-plan.json` | Record one bounded draft operation. | Action-plan builder | Handoff router and operator | One operation for `10.100.0.10`, draft status, and no egress. |
| `handoff.json` | Route the proposal without granting execution. | Specialist handoff router | Specialist and operator | Proposed status, pending approval, and matching plan digest. |
| `inert-observation.json` | Record the compact request seen by the child. | Local isolated child | Parent validator | Exact semantic match, one operation, and zero network requests. |
| `execution-evidence.json` | Bind the process result to captured bytes without retaining command-line data. | Parent runner | Operator and tests | Stable `python-isolated` identity and allowlisted `-I` flag are recorded only for the built-in dispatcher after the runner verifies its exact executable, flag position, child program, and argument count. Zero exit code, empty stderr, byte counts, and SHA-256 hashes are also required. Raw executable paths, inline program text, and arbitrary dispatcher arguments are omitted. |
| `playback-result.json` | Mark successful completion. | Parent runner | Catalog demo and operator | Exact documented six-field summary; written last. |

The [playback guide](docs/PLAYBOOK.md) defines each artifact's key fields,
producer, consumer, validation rule, and example in detail.

## Features

- **Engagement Intake**: Enforces explicit operator ownership, valid authorized windows, unambiguous targets, non-colliding exclusions, execution budgets, and credential references.
- **Scope Ambiguity Prevention**: Rejects wildcards, universal networks, and targets colliding with excluded boundaries.
- **Execution Mode Distinction**: Strictly differentiates between `planning`, `import`, `laboratory`, and `live` modes.
- **Live Safety Guard**: Prohibits live execution without mandatory budgets, emergency contact channels, active windows, and tight subnet scopes.
- **Action Plan Compilation**: Generates immutable `ActionPlan` (`cops.action-plan/v1`) contracts with exact caller-measured tool versions, platform prerequisites, expected evidence receipts, side effects, and verified cleanup obligations.
- **Triad Specialist Handoffs**: Emits and validates `SpecialistHandoff` (`cops.specialist-handoff/v1`) contracts coordinating Planner, Specialist, Skeptic, and Auditor with capability matching and re-approval triggers.
- **Scenario Laboratory Harness**: Registers and verifies operator container and VM environments with canary detection, isolation verification, reproducible resets, and controlled positive, negative, and remediated test execution.
- **Package Workflow and Capability Diagnostics**: Validates package manifests, skills, playbooks, host tool prerequisites, and capability truth-in-advertising diagnostics across all registered plugins and execution environments.
- **Model and Effort Suggestions**: Uses an operator-supplied host catalog to recommend an available model and sufficient reasoning effort for a bounded task, with separate capability and access checks.

## Installation and Runtime Availability

Use the workbench from a COPS repository checkout with Python 3.11 or newer. The local CLI, demo, and offline package check use the Python standard library; they do not require an AI assistant, cloud credentials, or additional pip packages. Clone the repository, then run the commands from its root:

```bash
git clone https://github.com/sodejm/copilot-operation-plugin-for-security.git
cd copilot-operation-plugin-for-security
python3 -m cops doctor
python3 -m cops info offensive-engagement-workbench
python3 -m cops demo offensive-engagement-workbench
python3 -m cops check offensive-engagement-workbench
```

Run the `python3 -m cops engagement`, `lab`, and `diagnostics` commands below from that same root. The package's `org.cops/prerequisites.json` declares no additional tools for package discovery and offline validation. Actual scenario operations can require separately provisioned and measured worker tools; the operator must supply their versions and authorization.

### AI assistant hosts and portable export

COPS publishes discovery metadata for these host surfaces. To install in an assistant, use that host's plugin or marketplace workflow to register the indicated marketplace and select `offensive-engagement-workbench`; grant only the filesystem and command permissions needed for the intended workflow. A host that invokes the local CLI also needs access to this checkout and Python 3.11 or newer.

| Host surface | Repository discovery entry | Package entry | Host setup to verify |
| --- | --- | --- | --- |
| GitHub Copilot | `.github/plugin/marketplace.json` | `plugin.json` | Copilot in VS Code or CLI, GitHub sign-in, and an active chat model. |
| Claude Code | `.claude-plugin/marketplace.json` | `.claude-plugin/plugin.json` | Plugin loading and permission prompts for the intended commands. |
| OpenAI Codex | `.agents/plugins/marketplace.json` | `.codex-plugin/plugin.json` | Plugin loading in the workspace and access to the checkout. |
| Agent Plugins v1.0.0 clients | Export with `python3 scripts/agent/export_portable.py --output dist/agent-plugins` | Exported `plugin.json` and `skills/` | Client support for Agent Plugins v1.0.0 and its runtime sandbox. |

The adapters and portable package are structurally checked, and the local workflow is validated offline. The package remains **experimental**: `host_installation` and `live_integration` are **unverified** in the repository's `package.json` for this package. After registering it, verify discovery and run a safe offline demo in the specific host before relying on that installation. Host permissions and plugin loading differ; see repository docs `docs/PORTABILITY.md` and `docs/COMPATIBILITY.md`.

The exported planning playback uses the shared COPS runtime and catalog, and its
specialist proposal reads the canonical `agents/registry.json`. Portable
acceptance supplies those framework files explicitly; the exported package does
not search for or fall back to a source checkout.

Planning and inventory inspection are portable CLI workflows. Authenticated external adapter execution has narrower platform requirements: the worker requires Linux with executable `/proc/self/fd`, while inert execution requires POSIX secure directory descriptors. Unsupported workers fail closed. These runtime limits and separate deployment checks are detailed in repository docs `docs/COMPATIBILITY.md` and `docs/AUTHENTICATED_EXECUTION.md`. Offline validation does not establish host installation or live execution readiness.

## Model and effort suggestions

Use the packaged [model-effort-routing skill](skills/model-effort-routing/SKILL.md)
and [catalog and preflight guide](docs/MODEL_ROUTING.md) before implementing an
issue or assigning security work. Run the advisor from the COPS checkout:

```bash
python3 -m cops route "Review the authorization boundary" \
  --suggest-model --model-catalog model-catalog.json \
  --current-model <exact-host-model-id> --current-effort medium --json
```

Daybreak, Fable, Mythos, Astra, and other families can qualify when the catalog
records the exact available model, granted access, sufficient capabilities, and
supported effort. Names alone do not qualify a model. The advisor runs offline;
it does not switch models or launch provider calls. The portable plugin includes
the skill and guide; executing the command also requires the COPS checkout and
Python 3.11 or newer described above.

## CLI Usage

```bash
# Create an engagement contract
python3 -m cops engagement create \
  --name "App Scope Review" \
  --owner "secops-operator" \
  --targets "10.100.0.10,app.internal" \
  --exclusions "10.100.0.1" \
  --start "2026-10-05T00:00:00Z" \
  --until "2026-10-05T23:59:59Z" \
  --budget-duration 1800 \
  --budget-output-bytes 5242880 \
  --output engagement.json

# Validate an engagement contract
python3 -m cops engagement validate engagement.json

# Compile an action plan
python3 -m cops engagement plan \
  --engagement engagement.json \
  --scenario COPS-E03.01-S01 \
  --target 10.100.0.10 \
  --tool-version python3=3.11.9 \
  --output action_plan.json

# Run Triad specialist handoff workflow
python3 -m cops engagement handoff workflow \
  --engagement engagement.json \
  --plan action_plan.json \
  --task "Network perimeter assessment" \
  --planner "secops-operator" \
  --output handoff.json

# Laboratory environment verification and case execution
python3 -m cops lab matrix
python3 -m cops lab register env.json
python3 -m cops lab verify env.json
python3 -m cops lab reset env.json
python3 -m cops lab run \
  --environment env.json \
  --plan action_plan.json \
  --authorization authorization.json \
  --worker-inventory worker-inventory.json \
  --authorization-trust-store authorization-trust.json \
  --engagement engagement.json \
  --case-type positive

# Capability and package workflow diagnostics
python3 -m cops diagnostics
python3 -m cops diagnostics --package offensive-engagement-workbench
python3 -m cops diagnostics --tools
```

## Planner Tool-Version Provenance

Measure the scenario operation tool through an independently trusted inventory or deployment workflow before compiling the plan. Supply its exact version with repeatable `--tool-version TOOL=VERSION` options. The planner records that value in the immutable operation; it does not inspect installed executables or establish that the measurement is accurate. A missing or blank version fails plan compilation, and the CLI rejects malformed entries or conflicting repeated values for the same tool.

The Python workflow requires the same explicit mapping:

```python
from pathlib import Path

from offensive_engagement_workbench import run_engagement_plan_workflow

summary = run_engagement_plan_workflow(
    Path("engagement.json"),
    tool_versions={"python3": "3.11.9"},
    target="10.100.0.10",
    scenario_id="COPS-E03.01-S01",
)
```

The worker owner separately provisions a worker capability inventory at execution time. Verification compares the signed plan's exact tool version with that independently provisioned inventory.

## Offline Verification Gate

```bash
python3 -m cops check offensive-engagement-workbench
```
