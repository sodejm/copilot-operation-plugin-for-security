# COPS — Copilot Operations Plugins for Security

<p align="center">
  <img src="docs/assets/cops-logo.png" alt="COPS shield and copilot visor logo" width="260">
</p>

<p align="center">
  <a href="https://sodejm.github.io/copilot-operation-plugin-for-security/"><img src="https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg" alt="Documentation Site"></a>
  <img src="https://img.shields.io/badge/python-3.11+-3776AB.svg?logo=python&logoColor=white" alt="Python 3.11+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-green.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/execution-100%25%20offline--first-success.svg" alt="Offline First">
  <a href="docs/COVERAGE_MATRIX.md"><img src="https://img.shields.io/badge/MITRE%20ATT%26CK-v18.0-orange.svg" alt="MITRE ATT&CK v18.0"></a>
  <img src="https://img.shields.io/badge/assistants-Copilot%20%7C%20Claude%20%7C%20Codex-purple.svg" alt="Universal Portability">
</p>

Welcome to **COPS (Copilot Operations Plugins for Security)**! COPS is an open-source, universal catalog of defensive cybersecurity plugins, 18 specialist agent profiles, and deterministic offline verification tools.

The [AI asset inventory](docs/AI_ASSET_INVENTORY.md) documents the bounded, offline evidence graph contract.

Whether your team works in **GitHub Copilot**, **Claude Code**, or **Codex / ChatGPT**, COPS provides production-grade cybersecurity capabilities without ecosystem lock-in. Everything is designed **offline-first**: you can explore tools, run demos, and validate detection logic directly from your local terminal using standard Python—no cloud credentials, assistant installations, or live tenant connections required.

📖 **Visit the complete [COPS Documentation Website](https://sodejm.github.io/copilot-operation-plugin-for-security/)** for interactive guides, playbooks, and reference architectures.

---

## Five-Minute Quickstart

All you need is **Python 3.11 or newer**. These commands use only the Python standard library and make zero external network calls:

```bash
# 1. Clone the repository and enter the directory
git clone https://github.com/sodejm/copilot-operation-plugin-for-security.git
cd copilot-operation-plugin-for-security

# 2. Check your local environment health
python3 -m cops doctor

# 3. List all 13 available security plugins and their status
python3 -m cops list

# 4. Route any natural language task to the best specialist agent
python3 -m cops route "Optimize Microsoft Sentinel KQL query for sign-in anomalies"

# 5. Inspect details and operational playbooks for a plugin
python3 -m cops info sentinel-hunt-workbench

# 6. Run a safe, offline demonstration with synthetic data
python3 -m cops demo sentinel-hunt-workbench

# 7. Run the plugin's complete offline test suite
python3 -m cops check sentinel-hunt-workbench
```

### What these commands do for you
- `cops doctor`: Quickly checks that your Python environment is ready and your package catalogs are in sync.
- `cops list`: Displays the thirteen available security plugins, their maturity stage, and their validation status.
- `cops route`: Deterministically routes any natural language task to the optimal specialist profile with zero LLM token cost.
- `cops demo`: Runs a self-contained, offline walkthrough using synthetic test data.
- `cops check`: Executes deterministic verification suites (syntax checks, schema tests, mutation tests) right on your machine.

---

## Available Security Plugins (13 Packages)

Each package lives in its own self-contained directory under `plugins/<category>/<plugin-id>/` and includes a complete practitioner playbook:

| Security Plugin | Category | Maturity | What it solves | Try it out |
| :--- | :--- | :---: | :--- | :--- |
| **[Security Logging Advisor](plugins/logging-telemetry/security-logging-advisor/README.md)** | Logging & Telemetry | <span class="badge badge-stable">Stable</span> | Audits codebases for security logging gaps, flags sensitive data leaks, and prioritizes CVE reachability. | `python3 -m cops demo security-logging-advisor` |
| **[Telemetry Proof Pack](plugins/logging-telemetry/telemetry-proof-pack/README.md)** | Logging & Telemetry | <span class="badge badge-beta">Beta</span> | Verifies end-to-end telemetry routes and pipeline health from Cribl Stream to Splunk and Sentinel. | `python3 -m cops check telemetry-proof-pack` |
| **[SOC Investigation Workbench](plugins/detection-hunting/soc-investigation-workbench/README.md)** | Detection & Hunting | <span class="badge badge-beta">Beta</span> | Guides alert triage using competing hypotheses, question ranking, and evidence dependency graphs. | `python3 -m cops demo soc-investigation-workbench` |
| **[Sentinel Hunt Workbench](plugins/detection-hunting/sentinel-hunt-workbench/README.md)** | Detection & Hunting | <span class="badge badge-beta">Beta</span> | Authors, adapts, and stress-tests 12 defensive Microsoft Sentinel and Defender KQL threat hunts offline. | `python3 -m cops demo sentinel-hunt-workbench` |
| **[Attack Path Workbench](plugins/detection-hunting/attack-path-workbench/README.md)** | Detection & Hunting | <span class="badge badge-experimental">Experimental</span> | Traces multi-hop cloud lateral movement paths from local exports to crown jewels and finds choke points. | `python3 -m cops demo attack-path-workbench` |
| **[Detection Quality Workbench](plugins/detection-hunting/detection-quality-workbench/README.md)** | Detection & Hunting | <span class="badge badge-beta">Beta</span> | Validates detection syntax, regressions, and quality metrics across Microsoft Sentinel KQL and Splunk SPL. | `python3 -m cops check detection-quality-workbench` |
| **[Threat Intelligence Enrichment](plugins/detection-hunting/threat-intelligence-enrichment/README.md)** | Detection & Hunting | <span class="badge badge-experimental">Experimental</span> | Enriches network, host, and hash indicators with provenance-tracked threat intelligence metadata. | `python3 -m cops check threat-intelligence-enrichment` |
| **[Entra Identity Workbench](plugins/identity-access/entra-identity-workbench/README.md)** | Identity & Access | <span class="badge badge-beta">Beta</span> | Evaluates Entra ID role assignments, service principals, consent grants, and credential exposures. | `python3 -m cops check entra-identity-workbench` |
| **[Exposure Triage Workbench](plugins/vulnerability-management/exposure-triage-workbench/README.md)** | Vulnerability Management | <span class="badge badge-beta">Beta</span> | Prioritizes vulnerability triage by correlating advisory CVEs, SBOM components, and call graph reachability. | `python3 -m cops check exposure-triage-workbench` |
| **[Patch Security Review](plugins/vulnerability-management/patch-security-review/README.md)** | Vulnerability Management | <span class="badge badge-beta">Beta</span> | Analyzes code patches and pull request diffs for dangerous patterns, authorization flaws, and regression risks. | `python3 -m cops check patch-security-review` |
| **[Attack Surface Planner](plugins/offensive-security/attack-surface-planner/README.md)** | Offensive Security | <span class="badge badge-experimental">Experimental</span> | Translates authorized rules of engagement into bounded, passive review plans from local export manifests. | `python3 -m cops demo attack-surface-planner` |
| **[Foundry Agent Harness](plugins/offensive-security/foundry-agent-harness/README.md)** | Offensive Security | <span class="badge badge-beta">Beta</span> | Evaluates AI agent behavior, prompt injection resistance, and safety boundaries in a simulated sandbox. | `python3 -m cops check foundry-agent-harness` |
| **[Incident Response Sandbox](plugins/incident-response/incident-response-sandbox/README.md)** | Incident Response | <span class="badge badge-beta">Beta</span> | Rehearses containment workflows, calculates blast radius, and generates cryptographic execution receipts. | `python3 -m cops check incident-response-sandbox` |

For in-depth guidance on choosing the right plugin for your operational scenario, see the **[When to Use Each Plugin Guide](docs/plugin-guide.md)**.

---

## 18 Specialist Cybersecurity Agent Profiles & Dynamic Routing

COPS centralizes **18 specialist cybersecurity agent profiles** in [`agents/`](agents/README.md) across offensive, defensive, forensics, identity, and governance disciplines. The deterministic zero-token router dynamically matches incoming tasks to the best specialist profile:

```bash
# Route any security request or natural language task:
python3 -m cops route "Optimize this Sentinel KQL query for low ingestion cost"

# List all 18 specialist profiles:
python3 -m cops specialists
```

For high-risk operations (e.g. penetration testing, red team emulation, active containment, or cloud privilege escalation), COPS automatically activates **Triad Orchestration** (Primary Specialist + Domain Skeptic + Evidence Auditor) with mandatory interactive operator authorization. Read the **[Specialist Agents Guide](docs/specialist-agents.md)** for architecture details.

---

## MITRE ATT&CK & Attack Flow Coverage

COPS capability logic, queries, and investigation workflows are formally mapped to the MITRE ATT&CK Enterprise Matrix (pinned v18.0) and MITRE Attack Flow:

- **[MITRE ATT&CK Coverage Matrix](docs/COVERAGE_MATRIX.md)**: Explore normalized technique mappings, coverage roles, validation states, and known bypass confounders.
- **[Coverage & Attack Flow Guide](docs/ATTACK_COVERAGE.md)**: Gap analysis separating missing telemetry from missing analytics, representative STIX 2.1 Attack Flow exports, and authoring guidelines.

---

## How Universal Portability Works

Different AI assistants expect different file structures, manifests, and skill formats. COPS removes that headache through automated, drift-free synchronization:

1. **One Source of Truth**: The central inventory in `catalog/plugins.json` defines all package metadata, versions, and categories.
2. **Standardized Packages**: Each plugin maintains its core Agent Plugins v1.0.0 manifest (`plugin.json`), host manifests (`.claude-plugin/`, `.codex-plugin/`), and reusable skills.
3. **Automated Host Marketplaces**: Running `python3 -m cops generate` automatically creates and synchronizes configuration files for:
   - **GitHub Copilot**: `.github/plugin/marketplace.json`
   - **Claude Code**: `.claude-plugin/marketplace.json`
   - **Codex / ChatGPT**: `.agents/plugins/marketplace.json`
4. **Guaranteed Consistency**: Our test gates verify that host indexes never drift out of sync with the catalog.

Learn more in the **[Portability Architecture](docs/PORTABILITY.md)** and **[Repository Layout](docs/REPOSITORY_LAYOUT.md)** guides.

---

## Contributor Setup

If you want to contribute new plugins, skills, or core features:

```bash
# Set up a dedicated virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install development test dependencies
python3 -m pip install -r requirements.txt

# Run the complete test suite
make check-prerequisites
make check PYTHON=.venv/bin/python
```

*(On Windows PowerShell, run `.\.venv\Scripts\Activate.ps1` to activate your environment).*

Before creating new plugins or modifying contracts, please review:
- **[Documentation Site](https://sodejm.github.io/copilot-operation-plugin-for-security/)**: The official documentation website.
- **[Getting Started Guide](docs/getting-started.md)**: Quickstart and command walkthroughs.
- **[Authenticated Execution Guide](docs/AUTHENTICATED_EXECUTION.md)**: Configure verifier trust, immutable approval binding, one-time execution, migration, and key rotation.
- **[Adding a Plugin](docs/ADDING_A_PLUGIN.md)**: Step-by-step instructions for contributing a new security capability.
- **[Troubleshooting Guide](docs/troubleshooting.md)**: Solutions for common setup and dependency issues.
- **[Repository Contract (AGENTS.md)](AGENTS.md)**: Coding conventions, git workflow, and branch rules.
- **[Contributing Guide](docs/contributing.md)**: Environment setup and testing workflows.

---

## Evidence & Safety Principles

In security engineering, confidence comes from verification:

- **Offline Safety**: Demos and checks run against local synthetic test data. They never make unreviewed network calls or write to remote production services.
- **Clear Status Separation**: We clearly separate what has been **validated locally** from what remains **unverified** in a live cloud environment. A passing offline test proves code correctness—it does not claim your production SIEM is currently receiving live alerts.
- **Data Privacy**: Tools treat all input code and logs as sensitive data. They do not store credentials or transmit telemetry to third parties.
- **Truth-in-Advertising**: Capabilities are audited into four operational readiness modes (`planned`, `import`, `laboratory`, `live-validated`), with zero false live claims.
- **Authenticated Execution Authority**: High-consequence execution requires a signed full-plan snapshot, the expected worker identity, an active engagement, an independent verifier trust store, and an owner-provisioned worker capability inventory. See the [Authenticated Execution Guide](docs/AUTHENTICATED_EXECUTION.md).
- **AI Component Verification**: Offline component identity, provenance and review-state reporting is documented in the [AI Component Verification Guide](docs/AI_COMPONENT_VERIFICATION.md); it never executes or fetches a component.

---

## License & Attribution

- COPS project code and documentation are licensed under the **[PolyForm Noncommercial License 1.0.0](LICENSE)**.
- Reusable components imported from PARK retain their original Apache-2.0 notices. See **[Third-Party Notices](THIRD_PARTY_NOTICES.md)** and **[Licensing Guide](docs/LICENSING.md)** for details.

### Plugin execution cost analysis

Contributors can use [plugin-run-cost](.agents/skills/plugin-run-cost/SKILL.md) to measure explicitly assigned COPS runs, estimate input scaling, and compare API, local-tool and employee costs. It runs locally with synthetic examples, preserves unknown charges, and distinguishes API-equivalent estimates from actual bills.

## Local pre-push validation

See [installation, prerequisites, security boundaries and recovery](docs/LOCAL_PUSH_GATE.md). CI remains required.
