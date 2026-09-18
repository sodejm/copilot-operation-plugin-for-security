# COPS project context

**COPS (Copilot Operations Plugins for Security)** is a security-specialized
project for cybersecurity plugins, agents, and skills. It contains
**COPS Security Logging Advisor** under `security-logging-advisor/` and the local
**COPS SOC Investigation Workbench** under `soc-investigation-workbench/`. The SOC
planner has two product skills; its canonical Sentinel integration is pending.
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

## SOC Investigation Workbench

- Package: `soc-investigation-workbench/`, with `.codex-plugin/plugin.json` and
  two registered skills for investigation planning and case review.
- Runtime: Python 3.10+ standard library, analyst-supplied redacted JSON cases,
  explicit evidence associations, question DAGs, deterministic next-step ranking,
  budgets, private snapshots, and review reports. No live query execution.
- Ownership: hunt design, raw telemetry correlation, KQL, rendering, compatibility,
  and qualification stay in canonical Sentinel skills. A hash-locked, unchanged
  copy of the entire Sentinel package supplies their supporting files. The
  canonical skills/catalog are pending; query handoffs fail until vendored.
- Specification: `specs/soc-investigation-workbench.spec.md`; ten matching
  scenarios in `specs/features/soc_investigation.feature` with behavior tests in
  `tests/step_defs/test_soc_investigation.py`.
- Validation: `make check` includes the development package check. The default
  `python3 soc-investigation-workbench/scripts/validate-package.py` command
  requires the vendor snapshot. `--allow-pending-vendor` is explicitly development
  only and never reports release readiness. See the package's `docs/validation.md`.

See [repository layout](../docs/REPOSITORY_LAYOUT.md),
[architecture](../ARCHITECTURE.md), and [security model](../docs/SECURITY_MODEL.md).
