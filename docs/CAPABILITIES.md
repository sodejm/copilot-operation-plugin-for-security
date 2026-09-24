# COPS cybersecurity capabilities

COPS packages defensive workflows so analysts can discover and exercise them from
one catalog before choosing a particular assistant host.

## Included packages

| Package | Maturity | Offline capability | Important boundary |
| --- | --- | --- | --- |
| [Security Logging Advisor](../plugins/logging-telemetry/security-logging-advisor/README.md) | Stable | Scans a local repository for technology and logging signals and supplies specialist logging guidance | Heuristics and recommendations require human review; host installation is unverified |
| [SOC Investigation Workbench](../plugins/detection-hunting/soc-investigation-workbench/README.md) | Beta | Validates evidence associations, hypotheses, question dependencies, budgets, and bounded next steps | Does not execute queries or response actions; Sentinel integration and live behavior are unverified |
| [Sentinel Hunt Workbench](../plugins/detection-hunting/sentinel-hunt-workbench/README.md) | Beta | Explains, renders, and deterministically stress-tests 12 defensive hunting workflows across declared surfaces | Reference evaluation is not Kusto or Microsoft Sentinel; tenant behavior and host installation are unverified |

Run `python3 -m cops list` for the machine-validated current inventory and support
states. Run `python3 -m cops info <plugin-id>` before use to see limitations and the
declared demo.

## Capability layers

Each package may contain three complementary layers:

- deterministic tools create or validate inspectable evidence;
- skills describe a reusable workflow and when it should be selected;
- agent instructions coordinate broader work that still needs judgment.

A package may omit optional host-specific agents or commands. It must provide a
canonical skill, the required Copilot, Codex, and Claude manifests, a governance
contract, documentation, a safe demonstration, and deterministic validation.

## Scope

Appropriate future categories include secure code review, threat modeling,
dependency assessment, cloud configuration review, detection engineering, digital
forensics, and incident triage. A roadmap entry is not a shipped capability. New
packages must define inputs, outputs, permissions, data handling, limitations, and
acceptance scenarios using [Adding a Plugin](ADDING_A_PLUGIN.md).

Product skills live inside their package. Shared `.agents/skills/` are contributor
workflows for maintaining COPS and are not part of the installable security catalog.
