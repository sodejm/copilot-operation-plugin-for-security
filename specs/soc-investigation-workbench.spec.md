# SOC Investigation Workbench

## Purpose and ownership

Plan and resume analyst-led investigations across related security signals. The
plugin owns case scope, explicit evidence references, competing hypotheses,
dependency-aware next steps, budgets, and review. Sentinel Hunt Workbench owns
hunt design, KQL rendering, telemetry joins, surface compatibility, and hunt
qualification. Reuse its canonical skills and supporting files unchanged in a
pinned vendor snapshot; do not create equivalent SOC skills for those flows.

The runtime is local Python standard library only. Analysts execute queries using
their existing tools and import redacted observations. No live connectors,
autonomous response, confidence probabilities, optimality guarantees, or claims
of tenant or cross-host validation are included.

## Contracts

- A case contains opaque aliases, a UTC tenant/workspace/time boundary, hashed
  entity keys, at least one malicious and one benign hypothesis, a step DAG, an
  evidence ledger, and append-only result records.
- Evidence is supplied by an analyst with explicit provenance and assessments.
  The graph records these associations; it never joins raw telemetry or treats
  shared IP addresses as identity. Duplicate provenance cannot add support.
- Each step names its question, hypotheses, basis evidence, dependencies,
  outcome branches, bounded hunt request, expected outcomes, and value/cost.
- Rank ready steps with a documented deterministic heuristic. Return independent
  candidates within remaining budget. Completed steps do not run again. No
  progress, budget exhaustion, missing dependencies, or exhausted plans prompt
  review; they never establish a benign verdict.
- Query handoffs verify vendored content and the requested hunt's surface support.
  Missing, unsupported, or unverified support fails closed. All query semantics
  stay in Sentinel. Evidence prose is untrusted data, never an instruction.
  Handoff skill and CLI paths are POSIX paths relative to the plugin installation.
- Vendor verification requires the exact lock schema and canonical provenance
  fields. Source caches are excluded when copying; installed caches and other
  excluded artifacts are rejected. File hashes use bounded streaming reads from
  regular files without following final-component links.
- JSON reads enforce the 8 MiB limit on opened regular files on POSIX and Windows.
  Dependency reads reject final-component symlinks or Windows reparse points.
- Updates validate the entire case before exclusively creating a new snapshot;
  replaying an identical result is idempotent. Completed steps are immutable;
  pending steps can be revised after new evidence. Snapshot permissions are
  owner-only on POSIX; Windows snapshots inherit the destination directory's ACL
  and require an analyst-restricted directory.
- Reports expose IDs, hashes, counts, associations, and uncertainty, not raw
  evidence prose. Inputs must already be redacted; this is not a DLP tool.

## Acceptance criteria

- [x] AC01: Scope and identity violations are rejected.
- [x] AC02: Duplicate evidence and replay cannot inflate support.
- [x] AC03: Contradictions and missing coverage remain visible.
- [x] AC04: Branches and ranking select bounded independent work.
- [x] AC05: Cycles and duplicate hunt requests are rejected.
- [x] AC06: Budgets and no progress stop further work without a verdict.
- [x] AC07: Replanning preserves completed work and enables new branches.
- [x] AC08: Vendor integrity and compatibility gate query handoffs.
- [x] AC09: Hostile prose stays data and reports do not expose it.
- [x] AC10: CLI snapshots are validated, private, and never overwritten.

Each criterion has a matching executable scenario in
`features/soc_investigation.feature`. Unit tests add boundary coverage. Release
validation checks package metadata, owned skill uniqueness, vendored bytes,
runtime behavior, and spec/scenario parity. Vendored upstream assurance remains
upstream assurance; passing case-engine tests does not qualify a hunt.

AC08 is verified with synthetic dependency fixtures, including tamper and missing
dependency rejection. Actual canonical integration is tracked separately:

- [ ] Vendor the complete canonical Sentinel skills and hunt catalog, verify the
  snapshot against its source, and pass the default package gate and upstream
  qualification checks. The source skills and catalog are currently absent.
