# COPS — Copilot Operations Plugins for Security

<p align="center">
  <img src="docs/assets/cops-logo.png" alt="COPS shield and copilot visor logo" width="260">
</p>

COPS (Copilot Operations Plugins for Security) is a cybersecurity project for
security-focused **plugins, agents, and skills**. It provides practical add-ons for
coding assistants that help developers and security teams understand repositories
and improve defensive security workflows.

The first included plugin, **COPS Security Logging Advisor**, combines a local
Python scanner, a specialist agent, and reusable skills for cost-aware security
logging reviews. See the [capability catalog](docs/CAPABILITIES.md) for what is
available today and how additional cybersecurity add-ons fit the project.

The scanner identifies languages, frameworks, cloud and infrastructure signals,
and potential credential locations. The advisor uses that context to recommend
structured audit events, redaction, correlation fields, and environment-specific
telemetry. Reports require review; pattern matching does not prove security or
compliance.

## Quick start

Use Python 3.11 or newer and Git. The scanner and package validator use only the
Python standard library. Contributor tests additionally require `requirements.txt`.

```bash
git clone https://github.com/sodejm/copilot-operation-plugin-for-security.git
cd copilot-operation-plugin-for-security
python3 plugins/logging-telemetry/security-logging-advisor/scripts/validate-plugin.py
python3 plugins/logging-telemetry/security-logging-advisor/skills/repository-context/scripts/collect-repository-context.py .
```

The scanner writes JSON to standard output. Give the agent the
[advisor instructions](plugins/logging-telemetry/security-logging-advisor/agents/security-logging-advisor.agent.md)
and reviewed context to produce a report. Follow the
[installation guide](plugins/logging-telemetry/security-logging-advisor/docs/INSTALL.md) for the host-specific
integration boundary and local fallback.

## SOC investigation planning

The separate [COPS SOC Investigation Workbench](plugins/detection-hunting/soc-investigation-workbench/README.md)
adds two Codex skills and a local Python case planner for evidence associations,
competing hypotheses, branching investigations, and bounded next steps. Hunt
workflows remain owned by Sentinel and are integrated through unchanged vendor
snapshots. The planner works locally; its Sentinel integration is pending the
canonical skills and catalog. See its README for setup and verified limits.

## Contributing

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
make doctor
make check
```

On Windows, activate `.venv\Scripts\Activate.ps1` in PowerShell. If Make is
unavailable, run `python3 scripts/agent/doctor.py` and
`python3 scripts/agent/check.py` directly.

Read [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before changing
the repository. COPS adopts the portable contracts, skills, adapters, and checks
from [PARK](https://github.com/sodejm/portable-agent-repository-kit). Edit canonical
skills in `.agents/skills/`, then run `make sync-agent-adapters`.

## Documentation

- [Documentation index](docs/INDEX.md) and [repository architecture](ARCHITECTURE.md)
- [Naming conventions](docs/NAMING.md) and [template adoption record](docs/decisions/0001-park-adoption.md)
- [Cybersecurity capabilities](docs/CAPABILITIES.md) and [GitHub discoverability](docs/DISCOVERABILITY.md)
- [Plugin architecture](plugins/logging-telemetry/security-logging-advisor/docs/architecture.md) and [model routing](plugins/logging-telemetry/security-logging-advisor/docs/model-routing.md)
- [Security and privacy](plugins/logging-telemetry/security-logging-advisor/docs/SECURITY_PRIVACY.md) and [security reporting](SECURITY.md)
- [Enterprise rollout](plugins/logging-telemetry/security-logging-advisor/docs/ENTERPRISE_ROLLOUT.md) and [maintainer guide](plugins/logging-telemetry/security-logging-advisor/docs/MAINTAINERS.md)
- [Plugin specification](specs/security-logging-plugin.spec.md) and [conformance specification](specs/repository-conformance.spec.md)

## License and attribution

Existing COPS project material retains the [PolyForm Noncommercial License 1.0.0](LICENSE).
Imported PARK material retains its Apache-2.0 notices; see
[third-party notices](THIRD_PARTY_NOTICES.md) and [licensing](docs/LICENSING.md).

## CVE reachability investigation

The packaged [CVE reachability agent](plugins/logging-telemetry/security-logging-advisor/agents/cve-reachability.agent.md) guides repository-specific investigations. Start with its [skill and runnable helper commands](plugins/logging-telemetry/security-logging-advisor/skills/cve-reachability/SKILL.md). The helper creates unresolved reports and checks evidence integrity and structure. Dependency resolution, call graphs, taint analysis and runtime validation require separate tools and analyst review; no automatic reachability proof or host installation is claimed. See the [workflow](plugins/logging-telemetry/security-logging-advisor/skills/cve-reachability/references/workflow.md) and [report contract](plugins/logging-telemetry/security-logging-advisor/skills/cve-reachability/references/report-contract.md).
