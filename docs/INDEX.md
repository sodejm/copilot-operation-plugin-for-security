# COPS Documentation Index

Welcome to the COPS documentation library! Whether you are exploring defensive tools for the first time, deploying plugins into your team's AI assistants, or authoring a new security package, you'll find everything you need organized below.

---

## 🚀 Getting Started

- **[Getting Started Guide](GETTING_STARTED.md)**: Go from a fresh repository clone to running safe package demos and tests in under five minutes.
- **[Cybersecurity Capabilities](CAPABILITIES.md)**: Explore the thirteen security packages across defensive and offensive domains covered by COPS.
- **[ATT&CK Coverage Matrix](COVERAGE_MATRIX.md)**: Explore normalized MITRE ATT&CK technique mappings and verified coverage across all COPS capabilities.
- **[ATT&CK & Attack Flow Guide](ATTACK_COVERAGE.md)**: Telemetry vs analytics gap analysis, representative Attack Flow exports, and authoring guidelines.
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
| **Entra Identity Workbench** | [Package Overview](../plugins/identity-access/entra-identity-workbench/README.md) | [Identity Governance Playbook](../plugins/identity-access/entra-identity-workbench/docs/PLAYBOOK.md) |
| **Exposure Triage Workbench** | [Package Overview](../plugins/vulnerability-management/exposure-triage-workbench/README.md) | [Exposure Triage Playbook](../plugins/vulnerability-management/exposure-triage-workbench/docs/PLAYBOOK.md) |
| **Foundry Agent Harness** | [Package Overview](../plugins/offensive-security/foundry-agent-harness/README.md) | [Adversarial AI Playbook](../plugins/offensive-security/foundry-agent-harness/docs/PLAYBOOK.md) |
| **Detection Quality Workbench** | [Package Overview](../plugins/detection-hunting/detection-quality-workbench/README.md) | [Detection Engineering Playbook](../plugins/detection-hunting/detection-quality-workbench/docs/PLAYBOOK.md) |
| **Patch Security Review** | [Package Overview](../plugins/vulnerability-management/patch-security-review/README.md) | [Patch Review Skill](../plugins/vulnerability-management/patch-security-review/skills/patch-review/SKILL.md) |
| **Threat Intelligence Enrichment** | [Package Overview](../plugins/detection-hunting/threat-intelligence-enrichment/README.md) | [Threat Intel Skill](../plugins/detection-hunting/threat-intelligence-enrichment/skills/threat-intelligence-enrichment/SKILL.md) |
| **Telemetry Proof Pack** | [Package Overview](../plugins/logging-telemetry/telemetry-proof-pack/README.md) | [Telemetry Proof Playbook](../plugins/logging-telemetry/telemetry-proof-pack/docs/PLAYBOOK.md) |
| **Incident Response Sandbox** | [Package Overview](../plugins/incident-response/incident-response-sandbox/README.md) | [IR Sandbox Skill](../plugins/incident-response/incident-response-sandbox/skills/incident-response-sandbox/SKILL.md) |

---

## 🏛️ Architecture & Portability

- **[Repository Architecture](../ARCHITECTURE.md)**: How the central catalog, packages, and automated host synchronization work together.
- **[Specialist Agent Profiles & Routing Guide](../agents/README.md)**: Centralized catalog of 18 callable specialist profiles, Triad orchestration, and dynamic zero-token routing.
- **[Repository Layout](REPOSITORY_LAYOUT.md)**: A complete map of directories, package boundaries, and file responsibilities.
- **[Universal Portability](PORTABILITY.md)**: How COPS generates configuration files for GitHub Copilot, Claude Code, and Codex without configuration drift.
- **[Shared Evidence SDK](EVIDENCE_SDK.md)**: Standardized evidence envelopes, pagination, and retry boundaries for data acquisition.
- **[Operational Contracts Specification](../specs/engagement-contracts.spec.md)**: Tamper-evident Engagement, Scenario, ActionPlan, RunResult, and Finding schema contracts.
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
