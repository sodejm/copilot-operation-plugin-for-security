# COPS cybersecurity capabilities

COPS (Copilot Operations Plugins for Security) develops practical cybersecurity
add-ons for coding assistants. Plugins package capabilities, specialist agents
guide security workflows, and skills provide reusable instructions and tools.
The scope includes defensive application security, security operations, and
repository-aware assistance for developers and security teams.

## Included today

| Component | Location | Capability |
| --- | --- | --- |
| COPS Security Logging Advisor plugin | `plugins/logging-telemetry/security-logging-advisor/` | Packages the agent, command, skills, and report assets |
| Security logging advisor agent | `plugins/logging-telemetry/security-logging-advisor/agents/` | Reviews repository context and recommends security logging improvements |
| Repository context skill | `plugins/logging-telemetry/security-logging-advisor/skills/repository-context/` | Uses a local Python scanner to identify technology signals and potential credential locations |
| Security logging recommendations skill | `plugins/logging-telemetry/security-logging-advisor/skills/logging-recommendations/` | Guides structured logging, redaction, audit events, and cost-aware telemetry recommendations |
| COPS SOC Investigation Workbench | `plugins/detection-hunting/soc-investigation-workbench/` | Local case engine and two Codex skills for scoped hypotheses, evidence associations, branching plans, budgets, and uncertainty review |

See [installation](../plugins/logging-telemetry/security-logging-advisor/docs/INSTALL.md) for running the
included tools and the boundary between local scripts and host integration.
Scanning is heuristic. Recommendations require review, and static package checks
do not establish compliance, vulnerability coverage, or support in every host.

The [SOC workbench guide](../plugins/detection-hunting/soc-investigation-workbench/README.md) provides a
synthetic local walkthrough. The planner is implemented, but its Sentinel skills
and hunt catalog must be vendored before query handoffs or release validation can
pass. No live connector, query execution, or autonomous response is included.

## Adding cybersecurity capabilities

Additional agents and skills may address areas such as secure code review,
threat modeling, dependency assessment, cloud configuration review, or incident
triage. These are contribution directions, not shipped features. Each addition
should define its security task, supported inputs, output evidence, permissions,
data handling, limitations, and validation in a focused specification.

Follow [naming conventions](NAMING.md) and the [contributor contract](../AGENTS.md).
Keep independently distributed product skills inside their package. The shared
`.agents/skills/` directory contains contributor workflows for maintaining COPS;
those workflows are separate from the installable cybersecurity product catalog.
