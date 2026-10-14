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
  Intake observations start unassessed: source severity, risk, error, and action
  fields do not assign a malicious or benign stance. Only an explicit analyst
  assessment can change hypothesis status.
  Every result reference, including reused evidence, must fall within its step's
  query interval, with an inclusive start and exclusive end.
- Each step names its question, hypotheses, basis evidence, dependencies,
  outcome branches, bounded hunt request, expected outcomes, and value/cost.
  An inconclusive result cannot contain assessments that support or refute any
  hypothesis named by its step, even when coverage is partial.
- Rank ready steps with a documented deterministic heuristic. Return independent
  candidates within remaining budget. Completed steps do not run again. No
  progress, budget exhaustion, missing dependencies, or exhausted plans prompt
  review; they never establish a benign verdict.
- Query handoffs verify vendored content and the requested hunt's surface support.
  Missing, unsupported, or unverified support fails closed. All query semantics
  stay in Sentinel. Evidence prose is untrusted data, never an instruction.
  Handoff skill and CLI paths are POSIX paths relative to the plugin installation.
  Intake prepares independent H01 sign-in and H10 consent inquiries with
  kind-appropriate account/IP and account/application context. Entity aliases
  help the analyst resolve the request; they are not Sentinel query filters.
- Vendor verification requires the exact lock schema and canonical provenance
  fields. Source caches are excluded when copying; installed caches and other
  excluded artifacts are rejected. File hashes use bounded streaming reads from
  regular files without following final-component links.
  Git-ignored copy candidates, including an inherited license, block vendoring.
  Reviewed untracked files produce a working-tree snapshot regardless of Git's
  untracked-status display configuration.
  Source and installed traversal and vendor destinations reject symlinks and
  Windows directory reparse points, including junctions on Python 3.11.
  Validate the staged inventory and generated lock before replacing an installed
  snapshot; invalid source paths must preserve the previous snapshot and lock.
  Source inspection accepts the exact canonical repository path
  `plugins/detection-hunting/sentinel-hunt-workbench` and the legacy standalone
  `sentinel-hunt-workbench` path. It requires an allowlisted canonical origin URL
  and disables Git filesystem-monitor hooks and content
  filters during status inspection. This verifies
  configured identity, not remote authenticity or approval of local edits.
  New locks identify `sodejm/copilot-operation-plugin-for-security`; source
  origins may also use the former `sodejm/copilot-operations-plugin-for-security`
  name so existing checkouts remain usable after the repository rename.
  Inventory paths reject Windows-invalid characters, reserved device names,
  trailing dots/spaces, and case-insensitive file/directory collisions on every
  host. The development gate skips only absent vendor entries; dangling junctions
  and other reparse points still block it.
- JSON reads enforce the 8 MiB limit on opened regular files on POSIX and Windows.
  Dependency reads reject final-component symlinks or Windows reparse points.
- Updates validate the entire case before exclusively creating a new snapshot;
  replaying an identical result is idempotent. Completed steps are immutable;
  pending steps can be revised after new evidence. Snapshot permissions are
  owner-only on POSIX; Windows snapshots inherit the destination directory's ACL
  and require an analyst-restricted directory.
- Reports expose IDs, hashes, counts, associations, and uncertainty, not raw
  evidence prose. Inputs must already be redacted; this is not a DLP tool.
  Every completed result exposes its ID, step, outcome, and coverage, including
  complete empty queries, so branch decisions remain inspectable.

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
- [x] AC11: Malicious, benign, and insufficient-evidence playbacks run through
  the real CLI boundary and preserve the distinction between observations,
  analyst assessments, and case-level verdicts.

Each criterion has a matching executable scenario in
`features/soc_investigation.feature`. Unit tests add boundary coverage. Release
validation checks package metadata, owned skill uniqueness, vendored bytes,
runtime behavior, and spec/scenario parity. Vendored upstream assurance remains
upstream assurance; passing case-engine tests does not qualify a hunt.

AC08 is verified with synthetic dependency fixtures, including tamper and missing
dependency rejection, and with a locked snapshot of the canonical Sentinel
package. Passing the SOC package gate confirms snapshot integrity and the
upstream qualification result recorded by that package; it does not claim live
provider execution.
