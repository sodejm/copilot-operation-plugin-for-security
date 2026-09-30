# COPS Documentation Index

Welcome to the COPS documentation library! Whether you are exploring defensive tools for the first time, deploying plugins into your team's AI assistants, or authoring a new security package, you'll find everything you need organized below.

---

## 🚀 Getting Started

- **[Getting Started Guide](GETTING_STARTED.md)**: Go from a fresh repository clone to running safe package demos and tests in under five minutes.
- **[Cybersecurity Capabilities](CAPABILITIES.md)**: Explore the five defensive security domains covered by COPS and choose the right tool for your mission.
- **[Adding a Plugin](ADDING_A_PLUGIN.md)**: Step-by-step instructions for contributing a new security capability to the catalog.
- **[Compatibility & Evidence](COMPATIBILITY.md)**: Learn what our offline tests prove, and how we keep offline proof distinct from live cloud claims.

---

## 🛠️ Package Guides & Playbooks

Each security plugin in COPS includes detailed documentation and a dedicated practitioner playbook:

| Security Plugin | Overview Guide | Step-by-Step Playbook |
| :--- | :--- | :--- |
| **Security Logging Advisor** | [Package Overview](../plugins/logging-telemetry/security-logging-advisor/README.md) | [AppSec & Telemetry Playbook](../plugins/logging-telemetry/security-logging-advisor/docs/PLAYBOOK.md) |
| **SOC Investigation Workbench** | [Package Overview](../plugins/detection-hunting/soc-investigation-workbench/README.md) | [SOC Analyst Playbook](../plugins/detection-hunting/soc-investigation-workbench/docs/PLAYBOOK.md) |
| **Sentinel Hunt Workbench** | [Package Overview](../plugins/detection-hunting/sentinel-hunt-workbench/README.md) | [Threat Hunter Playbook](../plugins/detection-hunting/sentinel-hunt-workbench/docs/PLAYBOOK.md) |
| **Attack Path Workbench** | [Package Overview](../plugins/detection-hunting/attack-path-workbench/README.md) | [Cloud Security Playbook](../plugins/detection-hunting/attack-path-workbench/docs/PLAYBOOK.md) |
| **Attack Surface Planner** | [Package Overview](../plugins/offensive-security/attack-surface-planner/README.md) | [Offensive Planner Playbook](../plugins/offensive-security/attack-surface-planner/docs/PLAYBOOK.md) |

---

## 🏛️ Architecture & Portability

- **[Repository Architecture](../ARCHITECTURE.md)**: How the central catalog, packages, and automated host synchronization work together.
- **[Repository Layout](REPOSITORY_LAYOUT.md)**: A complete map of directories, package boundaries, and file responsibilities.
- **[Universal Portability](PORTABILITY.md)**: How COPS generates configuration files for GitHub Copilot, Claude Code, and Codex without configuration drift.
- **[Shared Evidence SDK](EVIDENCE_SDK.md)**: Standardized evidence envelopes, pagination, and retry boundaries for data acquisition.
- **[Agent Skills Architecture](SKILLS.md)**: Authoring standards, line limits, and host-synchronization rules for reusable AI skills.
- **[Model Context Protocol (MCP)](MCP.md)**: Tool-server integration strategy and client configuration rules.
- **[Customization Guide](CUSTOMIZATION.md)**: How to tailor COPS for your organization without breaking upstream updates.

---

## 🔒 Security, Safety & Governance

- **[Security Model](SECURITY_MODEL.md)**: Threat modeling, prompt injection defenses, least-privilege boundaries, and data sanitization.
- **[Maintenance Workflows](MAINTENANCE.md)**: Upgrades, releases, and catalog integrity checks.
- **[Delivery Evidence Standard](DELIVERY_EVIDENCE.md)**: Maintaining strict honesty between local tests, commits, pull requests, and releases.
- **[Naming Conventions](NAMING.md)**: Project branding, naming guidelines, and asset identity rules.
- **[Licensing](LICENSING.md)**: Understanding PolyForm Noncommercial 1.0.0 and imported Apache-2.0 notices.
- **[Architectural Decision Records (ADRs)](decisions/README.md)**: Permanent records of key engineering decisions.
