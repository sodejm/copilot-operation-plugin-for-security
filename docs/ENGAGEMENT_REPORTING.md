# Offline engagement assessment reports

`python3 -m cops engagement report` joins existing Engagement, ActionPlan,
RunResult, Finding, and evidence-envelope contracts into one machine-readable
assessment and one Markdown report. It reads a local JSON bundle and makes no
network request or execution attempt. The provisional `COPS-E17.01` family
identifies this reporting workflow; it does not assert a canonical scenario
mapping or that a target was tested.

## Build a report

Prepare an input file that conforms to
[`assessment-input.schema.json`](../catalog/schemas/assessment-input.schema.json).
The bundle contains `schema_version` (`cops.assessment-input/v1`), `report_id`,
`generated_at`, one `engagement`, and arrays named `action_plans`, `run_results`,
`findings`, `evidence_envelopes`, `coverage`, `finding_contexts`, and `limitations`.
Embedded objects must satisfy their own published contracts. `coverage` contains
one row per scenario, target and mode, including a row for each RunResult. Each
row records `scenario_id`, `target`, `mode` (`planning`, `import`, `laboratory`, or
`live`), `access` (`available`, `unavailable`, or `unknown`), and a `result_id` or
`null`. A RunResult has one provenance mode and cannot be attached to planning
coverage. The [accepted bundle](../cops/contracts/fixtures/valid_assessment_input.json)
and [rejected conflicting-mode bundle](../cops/contracts/fixtures/invalid_assessment_input_conflicting_mode.json)
show that join rule. Every Finding needs a `finding_contexts` row with its `finding_id`, `kind`,
`affected_assets`, `reproducibility`, `attack_path_dependencies`, and
`limitations`. The four kinds are `configuration_observation`,
`scanner_assertion`, `observed_behavior`, and `reproduced_attack_path`.

With Python 3.11 or newer selected (see the [repository setup](../README.md)),
run this from the repository root to copy the accepted fixture into a private
directory outside the repository and build a report:

```bash
private_dir="$(mktemp -d)"
chmod 700 "$private_dir"
cp cops/contracts/fixtures/valid_assessment_input.json "$private_dir/assessment.local.json"
python3 -m cops engagement report \
  --input "$private_dir/assessment.local.json" \
  --json-output "$private_dir/assessment-report.local.json" \
  --markdown-output "$private_dir/assessment-report.local.md"
python3 -m cops contract validate --type assessment_report "$private_dir/assessment-report.local.json"
```

The input is limited to 4 MiB. Both output paths must be new and distinct; the
command refuses to overwrite files and creates each with owner-only permissions
(`0600` on POSIX). It emits no report body to standard output. Keep the directory
private; file permissions are not encryption or a guarantee against access by
another process with the same account.

## Read the assessment labels

The report lists included and excluded targets, per-target coverage, findings,
reproducibility, evidence record IDs and strength, attack path dependencies,
remediation, and limitations. Scope joins use exact hostnames or IP addresses and
CIDR containment; they do not infer related hosts. A host address and its
single-address CIDR (`/32` or `/128`) are the same target for duplicate checks.
A non-import RunResult cannot support coverage for different scenarios.
Missing access, a missing
RunResult, absent validated evidence, and planning-only rows are `not_assessed`.
Partial outcomes, scanner-only assertions, and historical imports cannot be
promoted to a complete assessment. Scanner-associated coverage needs an assessed
non-scanner Finding for the same RunResult and scenario, covering each asset
asserted by the scanner and sharing the row's validated evidence. An observation
on a different asset in a broad row cannot corroborate a scanner assertion.
An unverified observation does not corroborate a
scanner assertion. Live evidence needs an observation time within
its RunResult window; collection time alone does not establish when the target
was observed. An assessed Finding needs linked evidence for every affected asset.
If a broad coverage row is limited by an uncorroborated scanner assertion,
other Findings on that row remain partial unless separate assessed coverage
supports their affected assets.
A `reproduced_attack_path` requires repeatable, scoped laboratory or live evidence,
declared dependencies, and assessed prerequisite Findings. Contradicted findings
remain unresolved. Every dependency must name another Finding included in the
same report, appear once, and form an acyclic prerequisite chain. Each ActionPlan
must have a RunResult or a planning coverage row for its full, canonically equivalent target; a single-host row cannot represent a network-wide plan.

Validating a saved `assessment_report` also checks coverage, provenance, asset
joins, and Finding claims for contradictions, including scanner corroboration
and the match between a Finding's status and evidence strength. Coverage without
a RunResult cannot retain evidence references. The fixed `evidence_notice` trust
warning cannot be replaced. A `partial` Finding requires at least one matching
`partial` or `assessed` coverage row; linked evidence on exclusively
`not_assessed` coverage cannot support a partial claim. A Finding that names an
asset without assessed evidence must retain the generated
`Not assessed for assets: ...` limitation.
For a scanner assertion, partial evidence records collection that lacks
independent corroboration; it does not imply that collection for the named asset
was absent, so this asset-gap limitation is not required for that case:

| Assessment status | Verification | Evidence strength | Meaning |
| --- | --- | --- | --- |
| `assessed` | `verified` | `recorded` | Validated, linked evidence supports the scoped finding. |
| `partial` | `verified` or `unverified` | `limited` | Linked evidence exists, but the claim has a stated coverage or verification limit. |
| `not_assessed` | `verified` or `unverified` | `limited` or `missing` | Coverage or validated evidence is insufficient to assess the claim. |
| `unresolved` | `contradicted` | `contradicted` or `missing` | Conflicting evidence or missing validated evidence prevents a conclusion. |

`recorded`, `limited`, and `contradicted` require linked evidence records.
These combinations are necessary checks, not proof of a claim: saved-report
validation cannot reconstruct the input bundle or authenticate its source.
Retain the private source bundle for review.

Validated assessment-report objects can also be rendered as SARIF 2.1.0,
JUnit XML, or revision-bound PR Markdown through the local
[report export API](REPORT_EXPORTS.md). Its status mapping preserves
inconclusive and contradicted results instead of promoting them to verified
findings or successful tests. Exporting creates an artifact only; it does not
upload results or post a review.

`planned`, `imported`, `laboratory`, and `live_validated` are distinct provenance
labels; a live row that does not meet assessment requirements is
`live_unvalidated`. These labels describe the supplied, validated records. They
do not independently prove that execution happened, that a source is authentic,
or that an operator was authorized. Record hashes establish internal integrity
only. Verify those claims separately before sharing or relying on a report.

The renderer escapes Markdown punctuation and control characters in caller text.
It omits evidence payloads, credential references, source locators and
artifact paths. It does carry scope identifiers and caller-authored title, claim,
remediation, uncertainty and limitation text. Those fields can still contain
secrets or private information; review and redact the input and both outputs
before publishing. Historical data needs its own age and applicability assessment.
The report does not establish exhaustive coverage when scenarios or targets are
absent from the input.

## Validate detection coverage from imported evidence

`python3 -m cops engagement detection-validate` joins completed action IDs and
windows to the pinned ATT&CK detection mappings and supplied evidence envelopes.
It does not run an action, contact a telemetry provider, or prove source
authenticity or authorization. This workflow is an offline import. Start with the
[accepted input fixture](../cops/contracts/fixtures/valid_detection_validation_input.json)
or inspect the [rejected cross-tenant fixture](../cops/contracts/fixtures/invalid_detection_validation_cross_tenant.json).
The [four-outcome synthetic corpus](../cops/contracts/fixtures/valid_detection_validation_outcomes.json)
persists detected, missed, ambiguous, and unavailable examples for deterministic
offline playback through the public command. It validates import, classification,
and report generation only. It does not prove that an action ran, that a source is
authentic, that an action was authorized, that a provider search was complete, or
that a native SOC detected activity.
The [input contract](../catalog/schemas/detection-validation-input.schema.json)
requires an engagement, tenant, action windows, mapping/rule checks, and
`cops.evidence/v1` envelopes. The [workflow skill](../.agents/skills/engagement-detection-validation/SKILL.md)
describes the evidence collection and review steps.

The [E17.02 source traceability catalog](../catalog/detection_validation_source_traceability.json)
and its [schema](../catalog/schemas/detection-validation-source-traceability.schema.json)
link every pinned S01 through S13 source revision and inventory section to the
canonical scenario or guidance identifiers used by the repository. This static
catalog records theoretical source relationships only. Native SOC action and
alert correlation, collection completeness, clock alignment, and cleanup
evidence remain pending external execution; the catalog does not establish a
measured detection result.

```bash
private_dir="$(mktemp -d)"
chmod 700 "$private_dir"
cp cops/contracts/fixtures/valid_detection_validation_outcomes.json "$private_dir/detection.local.json"
.venv/bin/python -m cops engagement detection-validate \
  --input "$private_dir/detection.local.json" \
  --json-output "$private_dir/detection-report.local.json" \
  --markdown-output "$private_dir/detection-report.local.md"
.venv/bin/python -m cops contract validate --type detection_validation_report "$private_dir/detection-report.local.json"
```

The command reads at most 4 MiB, creates new owner-only files, and prints no
report body. Keep the source and report in a private directory. The JSON retains
the action ID, expected telemetry, imported record IDs, action/search windows,
limits, and a next action for each result. Markdown shows signal counts, limits,
and next actions while omitting raw evidence payloads and source locators.
Review IDs and private files before sharing.
The saved report contract check verifies structure, recomputes classifications
from the included signal summary, and checks action, observation, and search
window consistency. It cannot authenticate imported sources or prove that the
summary matches the original private input. Retain that input and independently
verify source authenticity and provider-wide search completeness when a result
must be audited or used operationally. For a `missed` result, verify the search
receipt before treating rule remediation as the next step.

`detected` requires an in-window execution observation and an exact, in-window
alert for the action and rule. `missed` requires completed execution, in-window
telemetry from an expected product and log with the catalog's required fields,
exact correlation, declared complete collection, and a completed
zero-result search receipt that covers the action window plus allowed clock skew
and ingest lag. `ambiguous` means the supplied evidence cannot distinguish these
outcomes. `unavailable` means execution was not completed or observed, or
collection was declared unavailable. A missing signal never proves prevention.
An alert outside the expanded observation window remains visible in the report
but does not contradict a covering zero-result search for that window.
The source notice names a separate trust boundary: record hashes establish
internal integrity, while provider-wide completeness and source authenticity
need independent verification before a measured result is used operationally.

## Retest findings and review closure

`python3 -m cops engagement retest` compares a saved baseline assessment with a
later assessment for the same engagement. It is an offline import: it does not
run a target assessment, approve a changed plan, or close a finding. The
[input contract](../catalog/schemas/retest-input.schema.json),
[report contract](../catalog/schemas/retest-report.schema.json), and
[workflow skill](../.agents/skills/engagement-retest-and-closure/SKILL.md)
describe the required records and review steps. Start with the
[accepted input fixture](../cops/contracts/fixtures/valid_retest_input.json):

```bash
private_dir="$(mktemp -d)"
chmod 700 "$private_dir"
cp cops/contracts/fixtures/valid_retest_input.json "$private_dir/retest.local.json"
python3 -m cops engagement retest \
  --input "$private_dir/retest.local.json" \
  --json-output "$private_dir/retest-report.local.json" \
  --markdown-output "$private_dir/retest-report.local.md"
python3 -m cops contract validate --type retest_report \
  --source-input "$private_dir/retest.local.json" \
  "$private_dir/retest-report.local.json"
```

The command reads at most 4 MiB and creates distinct, new output files with
owner-only permissions (`0600` on POSIX). It does not print the report body.
Keep the source and reports in a private directory and review identifiers and
free text before sharing.

Each result corresponds to one baseline finding and exact asset. `candidate_fixed` needs
an explicit `absent` check linked to assessed laboratory or live retest coverage
for the same scenario and exact asset. The linked record IDs must be absent
from the entire baseline report, with no matching finding
in the later report. `candidate_still_vulnerable` needs an explicit `present` check and a
matching assessed, corroborated finding. Missing checks, inaccessible or blocked
targets, changed asset identities, reused evidence, and contradictory findings
remain open as `not_assessed`, `inaccessible`, `blocked`, `identity_changed`, or
`evidence_gap`. Broad network coverage alone cannot establish absence for one
host.
Record-ID novelty does not prove the observation occurred after the baseline;
the saved coverage rows have no observation timestamp. Verify observation time
against the underlying evidence before closing a finding.

The report lists closure gates and next actions. Offline results remain candidates
and closure stays `blocked`, even when the supplied records pass consistency
checks. Recomputing with `--source-input` detects a saved report that differs
from its supplied input; it does not authenticate either source. Before closure,
independently authenticate
both source reports and the target observation, bind each supplied plan ID to
its actual plan and authorization, verify the owner acknowledgment and cleanup
in the target environment, and document residual risk and unresolved artifacts.
The input requires `residual_risks` (an empty array when none are recorded).
The private JSON and Markdown reports retain the owner reference and
acknowledgment, plan IDs, cleanup receipt statuses and unresolved effects, and
residual risks for review. Recorded residual risks require owner review until
an operator accepts or remediates them and updates the source record. These
fields can identify sensitive targets or artifacts; review them before sharing.
A receipt hash detects changes to selected receipt fields, and the importer
checks that its status agrees with the effect lists. The hash does not cover
status or timestamps and does not prove who issued the receipt or that cleanup
happened. The assessment report does
not contain a plan ID, so this importer cannot independently prove that the
supplied plan IDs belong to those reports. Every live retest requires verification
that its actual run used bound authority and that cleanup evidence belongs to that
run, even when the baseline and retest plan IDs match. A changed live plan needs
fresh authorization before execution unless a valid bound approval already
covers its exact actions and budget; this offline review cannot grant it.

For disposable laboratory executions, `verify_retest_execution_evidence_reference`
can verify a content-addressed `cops.laboratory-retest-evidence/v1` artifact
before producing a review input. The caller must supply a `TrustedLaboratoryContext`
loaded independently of the artifact: a verified disposable `LaboratoryEnvironment`,
the expected baseline `ActionPlan`, its target, and a provenance description naming
the trusted registration/baseline source. The verifier checks the environment's
verified isolation and canary state, the exact target, and the exact plan. An
environment or target copied from the artifact is not an independent trust source.
It rechecks persisted bytes, the exact plan and
authorization, supervisor response attestation, approval consumption, worker
observation, cleanup receipt, journal payload and result, and exact finding and
asset IDs. The caller must also provide
`trusted_terminal_journal_record_digest`, obtained from an independently trusted
terminal-journal source rather than copied from the evidence bundle. The verifier
requires that digest to match the persisted terminal journal record exactly. The
journal binds pre-execution observation references and the cleanup receipt
reference/digest; the current cleanup receipt model has no workspace
identity field, so this verifier does not claim to bind a workspace identity.
The caller must supply a snapshot of previously consumed authorization IDs; an
authorization present in that snapshot is rejected. This is a read-only prior-ledger
assertion, not an atomic consumption operation: concurrent reviewers require an
external durable transaction that records consumption before accepting a review.
A positive case maps to
`candidate_still_vulnerable`; an accepted remediated case maps to
`candidate_fixed`; a negative-control case maps to `blocked`, since a blocked
control is not affirmative evidence of remediation. This bridge supplies evidence for review; it does not rewrite
or bypass the existing offline importer, and closure remains blocked pending
independent review. Failed or indeterminate cases do not produce a reviewable
bundle.

The harness stages the review bundle inside the terminal case-journal record
before finalization. If writing the content-addressed bundle fails, call
`recover_retest_evidence_publication()` on a restarted harness using the same
protected journal and evidence store. Recovery republishes staged evidence
without dispatching the case or consuming authorization again. Durable review
verification checks the signed observation historically, then enforces its
chronology against the authenticated run, cleanup completion, and terminal
journal time; the live classification path still requires a fresh observation.
