# COPS changelog

## Unreleased

- Add centralized Specialist Cybersecurity Agent Profiles directory (`agents/`) with 27
  callable agent profiles across offensive security, defensive operations, incident
  response, digital forensics, identity governance, and compliance.
- Implement deterministic artifact and plain-language routing (`cops.routing` and
  `python3 -m cops route`) with calibrated scores, clarification, skill recommendations,
  and direct mentions. An explicitly configured classifier can assist uncertain routes.
- Propose Triad handoffs for critical operations (Primary Specialist, Domain Skeptic,
  Evidence Auditor). Routing does not start agents or authorize execution.
- Implement Interactive Authorization Gate (`cops.authorization`) with terminal prompts,
  signed execution authorizations bound to concrete plans, a one-use approval store,
  and fail-closed non-interactive behavior. Legacy checksum receipts are rejected.
- Add contributor skill `route-security-specialist` synchronized across agent platforms.
- Add CLI commands `cops route` and `cops specialists`.
- Add context-aware `cops explain`, execution previews, SARIF/JUnit/revision-bound
  Markdown report exports, typed workflows, and purple-team evidence handoffs.
- Add compliance, cloud posture, supply-chain CI/CD, secrets remediation, network
  segmentation, and TLS/crypto packages, and integrate the API inventory/replay
  workbench without replacing its formats. Extend existing packages with bounded
  offline artifact assessments and documented unsupported inputs.
- Add machine-readable playbooks and walkthroughs for all 25 packages, six integrated
  workflow definitions, synthetic fixtures, and portable runtime/asset synchronization.
- Add `make check-laboratory` as a separate required readiness gate. Functional
  loopback tests alone leave laboratory readiness incomplete. The Docker path uses
  a preinstalled immutable image, inspected isolation, real service activity,
  correlated telemetry, and verified restoration; live production validation remains
  separate. See [migration](docs/EXPANSION_MIGRATION.md) and
  [acceptance](docs/EXPANSION_ACCEPTANCE.md).

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
