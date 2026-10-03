# COPS — Copilot Operations Plugins for Security

<p align="center">
  <img src="docs/assets/cops-logo.png" alt="COPS shield and copilot visor logo" width="260">
</p>

Welcome to **COPS (Copilot Operations Plugins for Security)**! COPS is an open-source, universal catalog of defensive cybersecurity plugins, agent skills, and offline verification tools.

Whether your team works in **GitHub Copilot**, **Claude Code**, or **Codex / ChatGPT**, COPS gives you production-grade security capabilities without locking you into any single AI assistant ecosystem. Everything is designed **offline-first**: you can explore tools, run demos, and validate detection logic directly from your terminal using standard Python—no cloud credentials, assistant installations, or live tenant connections required.

---

## Five-Minute Quickstart

All you need is **Python 3.11 or newer**. These commands use only the Python standard library and make zero network calls:

```bash
# 1. Clone the repository and enter the directory
git clone https://github.com/sodejm/copilot-operation-plugin-for-security.git
cd copilot-operation-plugin-for-security

# 2. Check your local environment health
python3 -m cops doctor

# 3. List available security plugins and their status
python3 -m cops list

# 4. Inspect details and operational playbooks for a plugin
python3 -m cops info sentinel-hunt-workbench

# 5. Run a safe, offline demonstration
python3 -m cops demo sentinel-hunt-workbench

# 6. Run the plugin's complete offline test suite
python3 -m cops check sentinel-hunt-workbench
```

### What these commands do for you
- `cops doctor`: Quickly checks that your Python environment is ready and your package catalogs are in sync.
- `cops list`: Displays the five available security plugins, their maturity stage, and their validation status.
- `cops demo`: Runs a self-contained, offline walkthrough using synthetic test data.
- `cops check`: Executes deterministic verification suites (syntax checks, schema tests, mutation tests) right on your machine.

---

## Available Security Plugins

Each package lives in its own self-contained directory under `plugins/<category>/<plugin-id>/` and includes a complete practitioner playbook:

| Security Plugin | Category | What it solves | Try it out |
| :--- | :--- | :--- | :--- |
| **[Security Logging Advisor](plugins/logging-telemetry/security-logging-advisor/README.md)** | Logging & Telemetry | Audits codebases for security logging gaps, flags sensitive data leaks, and prioritizes CVE reachability. | `python3 -m cops demo security-logging-advisor` |
| **[SOC Investigation Workbench](plugins/detection-hunting/soc-investigation-workbench/README.md)** | Detection & Hunting | Guides incident investigations using competing hypotheses, question ranking, and evidence dependency graphs. | `python3 -m cops demo soc-investigation-workbench` |
| **[Sentinel Hunt Workbench](plugins/detection-hunting/sentinel-hunt-workbench/README.md)** | Detection & Hunting | Authors, adapts, and stress-tests 12 defensive Microsoft Sentinel and Defender KQL threat hunts offline. | `python3 -m cops demo sentinel-hunt-workbench` |
| **[Attack Path Workbench](plugins/detection-hunting/attack-path-workbench/README.md)** | Detection & Hunting | Traces multi-hop cloud lateral movement paths from local exports to crown jewels and finds remediation choke points. | `python3 -m cops demo attack-path-workbench` |
| **[Attack Surface Planner](plugins/offensive-security/attack-surface-planner/README.md)** | Offensive Security | Translates authorized rules of engagement into bounded, passive review plans from local export manifests. | `python3 -m cops demo attack-surface-planner` |

For an in-depth walkthrough and step-by-step guidance, read the **[Getting Started Guide](docs/GETTING_STARTED.md)** and review each plugin's **`docs/PLAYBOOK.md`**.

---

## Specialist Cybersecurity Agent Profiles & Dynamic Routing

COPS centralizes **18 specialist cybersecurity agent profiles** in [`agents/`](agents/README.md) across offensive, defensive, forensics, identity, and governance disciplines. The deterministic zero-token router dynamically matches incoming tasks to the best specialist profile:

```bash
# Route any security request or natural language task:
python3 -m cops route "Optimize this Sentinel KQL query for low ingestion cost"

# List all 18 specialist profiles:
python3 -m cops specialists
```

For high-risk operations (e.g. penetration testing, red team emulation, active containment, or cloud privilege escalation), COPS automatically activates **Triad Orchestration** (Primary Specialist + Domain Skeptic + Evidence Auditor) with mandatory interactive operator authorization.

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
make check
```

*(On Windows PowerShell, run `.\.venv\Scripts\Activate.ps1` to activate your environment).*

Before creating new plugins or modifying contracts, please review:
- **[Adding a Plugin](docs/ADDING_A_PLUGIN.md)**: Guidelines for contributing a new security capability.
- **[Repository Contract (AGENTS.md)](AGENTS.md)**: Coding conventions, git workflow, and branch rules.
- **[Contributing Guide](CONTRIBUTING.md)**: Environment setup and testing workflows.

---

## Evidence & Safety Principles

In security engineering, confidence comes from verification:

- **Offline Safety**: Demos and checks run against local synthetic test data. They never make unreviewed network calls or write to remote production services.
- **Clear Status Separation**: We clearly separate what has been **validated locally** from what remains **unverified** in a live cloud environment. A passing offline test proves code correctness—it does not claim your production SIEM is currently receiving live alerts.
- **Data Privacy**: Tools treat all input code and logs as sensitive data. They do not store credentials or transmit telemetry to third parties.

---

## License & Attribution

- COPS project code and documentation are licensed under the **[PolyForm Noncommercial License 1.0.0](LICENSE)**.
- Reusable components imported from PARK retain their original Apache-2.0 notices. See **[Third-Party Notices](THIRD_PARTY_NOTICES.md)** and **[Licensing Guide](docs/LICENSING.md)** for details.

### Plugin execution cost analysis

Contributors can use [plugin-run-cost](.agents/skills/plugin-run-cost/SKILL.md) to
measure explicitly assigned COPS runs, estimate input scaling, and compare API,
local-tool and employee costs. It runs locally with synthetic examples, preserves
unknown charges, and distinguishes API-equivalent estimates from actual bills.
