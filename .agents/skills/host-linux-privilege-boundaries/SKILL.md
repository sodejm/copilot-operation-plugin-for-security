---
name: host-linux-privilege-boundaries
description: Review bounded offline Linux privilege-boundary exports, preserving reported evidence and coverage limits.
---

# Linux privilege-boundary review

Use the `host-assessment-workbench` package for a local, sanitized v1 export.
Read its `docs/IMPORT_CONTRACT.md` and follow its
`skills/host-linux-privilege-boundaries/SKILL.md` workflow. Run the package
importer; do not collect host data or execute a privilege test from this skill.

Report each surface's coverage and prerequisite decision. Distinguish an
interesting configuration from a reported canary crossing, and preserve source
assertions as unverified until independent host evidence is available. If live
testing is needed, return the authorization, isolated worker, disposable host,
canary privilege, and cleanup requirements as the next action.
