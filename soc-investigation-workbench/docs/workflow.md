# Workflow and case contract

## Investigation loop

Scope → hypotheses and observations → bounded step graph → ranked ready work →
Sentinel handoff → analyst query execution → redacted result import → replan/review.

`scripts/investigate.py` is a local, deterministic Python CLI. It does not use an
LLM, network, or shell to interpret evidence. The two skills guide the host agent's
reasoning; the runtime enforces state and boundary checks. Run from the plugin
root, or call the script with an absolute path.

| Command | Result |
| --- | --- |
| `validate CASE` | Validate the complete case and print a canonical snapshot hash |
| `next CASE` | Rank ready steps and select a batch within remaining budget |
| `handoff CASE --step ID` | Verify vendor bytes and hunt/surface support; return canonical skill and CLI paths relative to the plugin installation |
| `import CASE RESULT --out NEW` | Deduplicate evidence and append one result to a new private snapshot |
| `revise CASE STEPS --out NEW` | Replace the pending plan; preserve completed steps exactly |
| `report CASE` | Print evidence references, associations, hypothesis states, coverage gaps, and next work |
| `verify-vendor [--source SOURCE]` | Check installed bytes, optionally compare a canonical source checkout |
| `vendor-sync SOURCE` | Maintainer-only explicit replacement from canonical Sentinel source |

Every mutation validates before creating its output, refuses existing paths
(including symlinks), and exits with code 2 on a contract or I/O error. Keep
snapshots in an analyst-controlled directory. This is an editable JSON ledger,
not a signed, tamper-evident case-management system. The hash fingerprints bytes
after canonical JSON serialization; it is not an authenticity proof. Outputs use
mode 0600 on POSIX; on Windows, access follows the destination directory's ACL.
Use an analyst-restricted directory on Windows. File mode does not secure
permissive parent directories or machine backups.

## Input shape

Use [case.json](../examples/case.json) and
[signin-result.json](../examples/signin-result.json) as complete templates.
Unknown/missing fields, duplicate JSON keys, non-finite numbers, and files larger
than 8 MiB are rejected. Lists are bounded to 1,000 entries. IDs are opaque
lowercase aliases matching `[a-z][a-z0-9_-]{0,63}`. Free text is 1–2,000 characters.

- Case: `schema_version: 1`, `id`, `scope`, `budget`, `hypotheses`, `entities`,
  `steps`, `evidence`, `results`.
- Scope: `tenant`, `workspace`, `start`, `end`. Times use
  `YYYY-MM-DDTHH:MM:SSZ`; intervals are half-open `[start,end)`. One case has one
  tenant/workspace boundary. For cross-workspace work, maintain separate cases
  and an analyst-reviewed summary instead of silently broadening scope.
- Budget: integer `max_steps`, `max_cost`, `max_no_progress` (1–10,000). Cost is
  an analyst-defined effort unit, consistently applied across steps; it is not
  measured API billing. An imported result must use its step's reserved cost.
- Hypothesis: `id`, `kind` (`malicious` or `benign`), `statement`. Include at least
  one malicious and one benign explanation. Distinct threat hypotheses can be supported together.
- Entity: `id`, `kind` (`account`, `app`, `device`, `ip`, `resource`), `key` (64
  lowercase hex characters). Use case-scoped HMAC-SHA256 digests or equivalently
  keyed opaque hashes for sensitive source IDs; keep keys and mappings outside
  the case. Format validation cannot establish that inputs are safely redacted.
  Identical kind/key pairs cannot acquire two aliases. A shared IP remains
  contextual, and no entity equivalence is inferred from it.
- Evidence: `id`, `source` alias, `record_ref` (64-hex opaque source-event digest),
  `scope` (tenant/workspace only), `event_time`, `entities` (IDs), `assessments`,
  `summary`. Each assessment is `hypothesis_id`, `stance` (`supports`/`refutes`),
  `reason`. Evidence stays in scope; new result evidence also stays in the query
  interval. An analyst supplies all associations and assessments. No raw-log
  joining, automatic identity resolution, or calibrated assessment occurs here.

Keep provenance stable across queries: `(source,record_ref)` identifies one
observation. Repeated provenance with identical content is deduplicated even
under a new evidence alias; conflicting content or an alias reused for a
different observation is rejected. Replaying an identical result ID and payload
is idempotent. Changed replays and repeat execution of completed steps fail.
Deduplication cannot discover the same real event under unrelated source IDs;
the analyst must normalize aliases and source references consistently.

## Plan and result shape

Each step has `id`, `question`, `hypothesis_ids`, `basis` (evidence IDs),
`depends_on` (step IDs), `when`, `query`, `expected`, and `value`.

- `when` is an AND list of `{step_id, outcomes}` guards. Each referenced step
  must be a direct dependency. Outcomes within a guard are OR alternatives.
  Empty `when` means all dependencies must complete, regardless of outcome.
- `query`: `hunt_id` (catalog Hxx), `surface`, `entities` (aliases), `start`, `end`.
  Surfaces are `sentinel_analytics`, `sentinel_data_lake`, and
  `defender_advanced_hunting`. A valid case may contain a planned unverified
  surface; the handoff rejects it. Duplicate query tuples are rejected; reuse
  their evidence. Changing entity sets/windows can still produce overlapping
  queries, so review near-duplicates with the canonical hunt workflow.
- `expected`: text for each of `supports`, `refutes`, `empty`, `unavailable`, and
  `inconclusive`, explaining what each observation would mean for the question.
- `value`: integers `information_gain`, `urgency`, `impact` (0–5), `cost` (1–10,000).

The result import file contains `id`, `step_id`, `outcome`, `coverage`, `cost`,
and `evidence` (full observation objects). Coverage is `complete`, `partial`, or
`unavailable`. `supports`/`refutes` require a matching explicit assessment for
one of the step's hypotheses. These aggregate branch labels do not classify
every hypothesis: inspect each assessment when multiple hypotheses are involved.
Complete coverage with no observations must use `empty`; it adds no refutation.
An `empty` outcome also requires complete coverage and no observations.
`unavailable` requires unavailable coverage and no observations. Use
`inconclusive` only when no returned evidence supports or refutes any of the
step's hypotheses. Partial coverage alone does not make an assessed finding
inconclusive. Complete observations without relevant assessments may also be
inconclusive; complete coverage with no observations remains `empty`.

Stored results replace full observations with `evidence_ids`,
`new_evidence_ids`, and `input_hash`. Do not hand-edit these fields. The engine
validates historical dependencies, branch outcomes, evidence visibility, cost,
and stopping rules when reopening a case. Step revision takes a JSON **array**
of steps, preserving every completed entry. Adding a new pending branch is
supported. Changing case scope, hypotheses, or entities is not exposed as a
mutation command in this MVP; those require a separately reviewed case snapshot.

Reports include `completed_results` with each result's ID, step ID, outcome, and
coverage. Review these alongside coverage gaps and hypothesis assessments to
explain why a branch became eligible, including after a complete empty query.
Evidence summaries and assessment reasons remain excluded from reports.

## Selection and uncertainty

Only uncompleted steps whose dependencies, guards, and evidence basis are ready
are ranked. A deterministic greedy batch uses:

`(3 × information_gain + 2 × urgency + impact + contradiction_bonus) / cost`

The bonus is 3 if any linked hypothesis has both supporting and refuting
assessments. Ties use step ID. Candidates expose all score components. Selection
skips steps that cannot fit remaining cost/step slots and caps the batch at the
remaining no-progress allowance, so every selected result can be recorded even
if all return no new observations. New evidence resets that allowance when the
next batch is planned. Selected steps have no
unfinished dependencies on each other. It optimizes an explainable heuristic,
not expected entropy or a global optimum. Estimates remain analyst judgment.

Stop for review when step/cost limits are reached, when the last
`max_no_progress` completed results add no new observations, or when no eligible
work fits. Empty and duplicate-only results consume effort. The no-progress rule
is deliberately conservative: an empty query can be informative, so the analyst
may need a new reviewed plan/case after a stop. No result budget can be bypassed
by editing pending steps through `revise`.

Hypothesis status is `unresolved`, `support_observed`, `refutation_observed`, or
`contested`. These describe the ledger, not verified truth or probability. An
exhausted plan, empty query, or unavailable source never generates a benign
verdict. Reports omit summaries/reasons and retain IDs, graph edges, and gaps.
Free text must be redacted before import, and instruction-like event text must
never control the host agent or its tools.
