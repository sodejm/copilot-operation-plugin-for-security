# Specification: COPS repository conformance

## Scope

Adopt Portable Agent Repository Kit (PARK) revision
`bfc41923fb497b495e95dc7dee644313b51b368b` as a configured project foundation.
Use **COPS (Copilot Operations Plugins for Security)** for the repository and
**COPS Security Logging Advisor** for the existing plugin's display name.
Keep the `security-logging-advisor` package, command, agent and marketplace IDs
stable. Preserve the existing project license and scanner behavior.
Position COPS as a security-specialized project for cybersecurity plugins, agents,
and skills; distinguish included capabilities from potential future add-ons.

## Requirements

- Root `AGENTS.md` owns contributor instructions; vendor adapters point to it.
- Canonical contributor skills live in `.agents/skills/`; generated Claude copies
  must match. Distributed product skills remain inside their plugin packages.
- `make check` validates the repository contract, Markdown links, Python syntax,
  adapter drift, plugin package, plugin unit tests, pytest scenarios, and bundled
  skill tests. Failures must produce a nonzero exit status.
- The SOC package check permits an entirely absent Sentinel snapshot for local
  development and reports that limitation. Its separate default release gate
  requires verified vendored content; repository CI does not establish release
  readiness or qualify Sentinel hunts.
- Contract checks include repository sources and newly added files, exclude
  Git-ignored local artifacts, and do not follow symlinks outside the checkout.
- Documentation describes actual local commands and distinguishes static checks
  from host integration or publishing evidence.
- Imported PARK material retains its Apache license and recorded provenance.

## Verification

The scenarios in [repository_conformance.feature](features/repository_conformance.feature)
cover source enumeration and portable model guidance. Their executable steps live
in `tests/step_defs/test_repository_conformance.py`. Existing scanner and package
scenarios remain part of the aggregate gate. Adapter drift is checked by
`make check-agent-adapters`; repository link and skill checks run in
`make validate-contract`. Host installation and publication are separate checks.
