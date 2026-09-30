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
- [x] APW-11: Read untrusted manifests and sources through a shared descriptor-anchored ingestion boundary. Reject links, special files, unsupported compression, oversized or deeply nested JSON, and exhausted file, byte, or record budgets before report completion. Record effective limits and usage in the report.

## Evidence and safety constraints

The engine has no network client. Raw export records are retained by source hash and pointer, but are not blindly promoted to normalized facts. All source and context content is untrusted data. Incomplete or unknown export coverage remains explicit. Capability transitions are conditional scenarios, and path confidence means evidence support only. No likelihood or NIST rating is inferred.

## Azure entitlement analysis (#26)

The additive `analyze-azure` command accepts a bounded local manifest of pinned
Graph/ARM response pages wrapped in `cops.evidence/v1` and acquisition receipts.
It requires an explicit UTC analysis time and controlled-principal/target scenario.
It preserves tenant-qualified identities, direct membership witnesses, temporal
assignments, scope ancestry, separate control/data permissions and source uncertainty.
The legacy illustrative engine and its identifiers remain stable.

- AZ-01: Validate hashes, receipts, pagination, supported APIs and allowlisted
  projections before permission reasoning. Reject unsafe paths and malformed data.
- AZ-02: Resolve role-local exclusions, denies, supported conditions, group witnesses,
  directory object scopes, PIM activation and restricted Lighthouse delegation.
- AZ-03: Model explicit hypothetical grants, credential changes, identity attachment,
  VM, Automation, Functions, Logic Apps and federation routes with exact rights
  and runtime prerequisites. ARM deployment execution requires all supported
  deployment operations at the resource group and underlying extension rights on
  an observed VM. Vault write alone never establishes secret access.
- AZ-04: Bound traversal and counterfactual work; emit deterministic reachable,
  conditional, latent, blocked or unknown paths with evidence and uncertainty.
- AZ-05: Export a typed graph, evidence ledger, safe Markdown and ranked JSON,
  optionally pseudonymized. Suggest narrow cuts only after bounded re-analysis.
- AZ-06: Generate bounded read-only Graph, ARM and Resource Graph inventory plans
  for declared scopes, including endpoint versions, least-privilege permissions,
  completeness limits and SDK shapes. Resource Graph inventory is scope-bounded,
  can omit inaccessible resources and requires typed ARM follow-up evidence.
- AZ-07: Execute paired fixtures for every supported resource family, including
  deployment exclusions and missing underlying rights, and exercise realistic SDK
  bundles through the standalone exported CLI with no network access.
- AZ-08: Apply the shared ingestion boundary to manifests, acquisition receipts,
  and JSONL sources. Count page envelopes and projected records against one record
  budget; bound physical lines and JSON depth; reject exhausted budgets before
  producing a completion marker. CLI limits may only tighten manifest limits.

Modelled reachability establishes supported predicates in supplied evidence and
scenario assumptions; it does not establish compromise or successful exploitation.
Missing or unsupported prerequisites remain visible. No command authenticates,
collects live data, changes entitlements, retrieves secrets or executes remediation.
