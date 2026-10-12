# COPS Offensive Engagement Workbench

`offensive-engagement-workbench` provides authorized adversarial assessment intake, scope boundary validation, execution mode classification, and reviewable immutable action planning for the Copilot Operations Plugin for Security (COPS) ecosystem.

Follow the [end-to-end verification playbook](docs/VERIFICATION.md) to qualify this
package's documented workflow and prepare evidence for a maturity review.

## Features

- **Engagement Intake**: Enforces explicit operator ownership, valid authorized windows, unambiguous targets, non-colliding exclusions, execution budgets, and credential references.
- **Scope Ambiguity Prevention**: Rejects wildcards, universal networks, and targets colliding with excluded boundaries.
- **Execution Mode Distinction**: Strictly differentiates between `planning`, `import`, `laboratory`, and `live` modes.
- **Live Safety Guard**: Prohibits live execution without mandatory budgets, emergency contact channels, active windows, and tight subnet scopes.
- **Action Plan Compilation**: Generates immutable `ActionPlan` (`cops.action-plan/v1`) contracts with exact caller-measured tool versions, platform prerequisites, expected evidence receipts, side effects, and verified cleanup obligations.
- **Triad Specialist Handoffs**: Emits and validates `SpecialistHandoff` (`cops.specialist-handoff/v1`) contracts coordinating Planner, Specialist, Skeptic, and Auditor with capability matching and re-approval triggers.
- **Scenario Laboratory Harness**: Registers and verifies operator container and VM environments with canary detection, isolation verification, reproducible resets, and controlled positive, negative, and remediated test execution.
- **Package Workflow and Capability Diagnostics**: Validates package manifests, skills, playbooks, host tool prerequisites, and capability truth-in-advertising diagnostics across all registered plugins and execution environments.

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

Planning and inventory inspection are portable CLI workflows. Authenticated external adapter execution has narrower platform requirements: the worker requires Linux with executable `/proc/self/fd`, while inert execution requires POSIX secure directory descriptors. Unsupported workers fail closed. These runtime limits and separate deployment checks are detailed in repository docs `docs/COMPATIBILITY.md` and `docs/AUTHENTICATED_EXECUTION.md`. Offline validation does not establish host installation or live execution readiness.

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
