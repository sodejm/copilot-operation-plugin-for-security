---
name: documentation-impact
description: Determine and implement the documentation changes required by code, configuration, workflow, architecture, security, or release changes.
---

# Documentation impact

Map the change to affected audiences and durable sources of truth:

- users: README, guides, examples, compatibility, migration;
- contributors: setup, commands, tests, conventions, agent instructions;
- maintainers: architecture, decisions, operations, release, rollback;
- security: policy, threat model, permissions, data handling, disclosure;
- automation: generated adapters and contract validation.

Update documentation in the same change and verify commands, paths, examples, and
links. Do not document proposed behavior as implemented. If no documentation change
is needed, provide a short, specific rationale.
