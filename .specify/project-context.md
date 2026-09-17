# COPS project context

**COPS (Copilot Operations Plugins for Security)** is a security-specialized
project for cybersecurity plugins, agents, and skills. It currently contains one
plugin, **COPS Security Logging Advisor**, with its agent and two product skills,
stored under `security-logging-advisor/`. Additional defensive cybersecurity
add-ons are within the project's scope; they are not yet implemented.
Stable IDs are listed in [naming conventions](../docs/NAMING.md).

Python implements deterministic local scanning and package validation using the
standard library. Markdown holds instructions and report assets; JSON holds
manifests and examples. Python 3.11+ is the contributor baseline, with pytest and
pytest-bdd for executable scenarios. Detected repository technologies such as
Terraform are scanner inputs, not dependencies of COPS.

The scanner is
`security-logging-advisor/skills/repository-context/scripts/collect-repository-context.py`.
Report assets live in each product skill's `assets/` directory. The package
validator is `security-logging-advisor/scripts/validate-plugin.py`.

PARK-derived contributor workflows live under `.agents/`, with generated
`.claude/skills/` copies. Root `AGENTS.md` is canonical across environments.
`make check` combines portable contract checks, adapter drift detection, plugin
validation, unit tests, BDD scenarios, and bundled skill tests. GitHub Actions
runs that gate for pull requests and pushes to `main`. No marketplace publication
or deployment workflow is configured.

See [repository layout](../docs/REPOSITORY_LAYOUT.md),
[architecture](../ARCHITECTURE.md), and [security model](../docs/SECURITY_MODEL.md).
