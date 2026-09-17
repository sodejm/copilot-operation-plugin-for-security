# 0001: Adopt PARK as the COPS repository foundation

Status: accepted for local implementation by the repository owner's request.
Date: 2026-09-16.

## Context

COPS previously had IDE-specific instructions, separate plugin checks, and
inconsistent project naming. The owner requested conformance with PARK and the
name Copilot Operations Plugins for Security.

## Decision

Adopt configured-project output from PARK revision
`bfc41923fb497b495e95dc7dee644313b51b368b`. Root `AGENTS.md` owns policy; portable
skills are canonical and Claude copies are generated. Extend the baseline
`make check` with existing plugin unit and pytest-bdd tests. Preserve plugin paths,
IDs, behavior specifications, original license and the separate product skills.
Record Apache attribution for imported foundation files.

## Alternatives and consequences

A wholesale replacement would discard the existing product and license. A naming
change alone would leave conflicting instructions and incomplete checks. The
chosen adaptation preserves the product while giving all contributors one gate.
The full gate now requires the existing pytest development dependencies. Vendor
installation remains a separately tested integration; static validation is not
proof of host support. Future PARK upgrades require reviewed diffs against this
recorded revision rather than copying over COPS-specific policy.
