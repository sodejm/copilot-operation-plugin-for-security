# Changelog

All notable changes to the **COPS Security Logging Advisor** plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Adopt COPS Security Logging Advisor as the display name; preserve package and marketplace IDs.
- Align documentation and contributor checks with the COPS portable repository foundation.

### Fixed

- Reject ambiguous duplicate JSON keys and nonstandard numeric constants in reachability reports.
- Handle evidence symlink loops cleanly across supported Python versions.

### Added

- CVE reachability investigation agent, skill and guide with parameter-level analysis, dispatch review, scoped conclusions and evidence requirements.
- Standard-library CLI for unresolved report initialization, evidence fingerprints and report integrity checks. It does not validate semantic reachability or tool capabilities.
- CLI integration and adversarial tests; static package wiring checks. Host installation and external analyzers remain unverified.

## [1.0.0] - 2026-07-03

### Added

- **Plugin Manifests**: Created `plugin.json`, `.github/plugin/marketplace.json`, and `.claude-plugin/marketplace.json`.
- **Core Agent & Skills**: Defined agent instructions and skills for repository scanning and logging recommendations.
- **Python Scripts**: Added deterministic scanner `collect-repository-context.py` and validator `validate-plugin.py`.
- **Templates**: Structured templates for repository context analysis and logging recommendation reports.
- **Examples**: Included sample structured logging configs for Node.js (Pino) and Python (Structlog).
- **Documentation**: Formulated `INSTALL.md`, `ENTERPRISE_ROLLOUT.md`, `SECURITY_PRIVACY.md`, `TROUBLESHOOTING.md`, and `MAINTAINERS.md`.
