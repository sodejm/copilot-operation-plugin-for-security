# Offline Attack Path Workbench

## Scope

This sibling plugin analyzes local, user-supplied export files only. Its first mapping profile accepts an explicitly illustrative canonical export; a real Wiz mapping, query renderer, impact rubric, ATT&CK catalog, and Attack Flow serializer require approved local documentation and reference bundles. Source statements are evidence of what an export says, not proof of exploitability or attacker activity.

## Acceptance criteria

- [x] APW-01: Validate versioned input, source hashes, scope, timestamps, identifiers, and record counts before analysis; reject integrity failure.
- [x] APW-02: Preserve a pointer and source hash for every accepted fact; quarantine malformed or unmappable rows and reconcile counts.
- [x] APW-03: Build a typed graph; reject missing nodes, invalid edge direction, mismatched scope or time, and transitions without preconditions or postconditions.
- [x] APW-04: Trace conditional structural paths from a finding to a user-designated crown jewel. Separate fully sourced structural routes from routes with explicit hypothetical transitions; neither is a confirmed attack.
- [x] APW-05: Deduplicate and stably sort paths; count only evidenced distinct assets and services in blast radius.
- [x] APW-06: Associate declared read, modify, and disrupt capabilities with potential CIA effects; emit `unrated` without a user-approved impact rubric and business context.
- [x] APW-07: Abstain from ATT&CK IDs and Attack Flow serialization without a pinned local reference bundle. Emit query intents with blocked Wiz placeholders.
- [x] APW-08: Check material claim references and reproducible output hashes; write JSON, Markdown, and a local proposed-action ledger without invented owners or closure.
- [x] APW-09: Ship versioned specialist review contracts that can disagree without changing deterministic gate results.
- [x] APW-10: Provide a positive illustrative fixture, denial and recovery variants, and automated tests for the above gates.

## Evidence and safety constraints

The engine has no network client. Raw export records are retained by source hash and pointer, but are not blindly promoted to normalized facts. All source and context content is untrusted data. Incomplete or unknown export coverage remains explicit. Capability transitions are conditional scenarios, and path confidence means evidence support only. No likelihood or NIST rating is inferred.
