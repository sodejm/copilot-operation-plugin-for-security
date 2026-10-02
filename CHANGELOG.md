# COPS changelog

## Unreleased

- Add centralized Specialist Cybersecurity Agent Profiles directory (`agents/`) with 18
  callable agent profiles across offensive security, defensive operations, incident
  response, digital forensics, identity governance, and compliance.
- Implement deterministic, zero-token dynamic agent routing engine (`cops.routing` and
  `python3 -m cops route`) with confidence scoring, skill recommendations, and direct mentions.
- Implement Triad Orchestration Topology for critical operations, assembling a coordinated
  three-agent team (Primary Specialist, Domain Skeptic, Evidence Auditor) with defined handoffs.
- Implement Interactive Authorization Gate (`cops.authorization`) with terminal prompts,
  cryptographically signed SHA-256 receipts (`AuthorizationReceipt`), and fail-closed non-interactive behavior.
- Add contributor skill `route-security-specialist` synchronized across agent platforms.
- Add CLI commands `cops route` and `cops specialists`.

- Add COPS SOC Investigation Workbench with two Codex skills, a local case planner,
  evidence and scope checks, branching next-step selection, and tested Sentinel
  vendoring. Canonical Sentinel skills/catalog integration is pending and blocks
  query handoffs and release validation.

- Position COPS as a cybersecurity project for plugins, agents, and skills; document the included capabilities and focused GitHub topics.

- Adopt PARK's portable repository contract, contributor skills, generated Claude
  adapters, documentation, GitHub templates, and validation workflow.
- Integrate plugin validation, unit tests and BDD scenarios into `make check`.
- Rename project documentation and plugin display names to COPS (Copilot
  Operations Plugins for Security), preserving package and marketplace IDs.
- Add the COPS shield and copilot logo, naming guidance and template provenance.
- Correct stale scanner paths and unsupported setup, model and release claims.

Plugin release history remains in
[plugins/logging-telemetry/security-logging-advisor/CHANGELOG.md](plugins/logging-telemetry/security-logging-advisor/CHANGELOG.md).
