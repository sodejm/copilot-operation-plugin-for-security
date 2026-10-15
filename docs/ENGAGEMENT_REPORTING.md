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
The [input contract](../catalog/schemas/detection-validation-input.schema.json)
requires an engagement, tenant, action windows, mapping/rule checks, and
`cops.evidence/v1` envelopes. The [workflow skill](../.agents/skills/engagement-detection-validation/SKILL.md)
describes the evidence collection and review steps.

```bash
private_dir="$(mktemp -d)"
chmod 700 "$private_dir"
cp cops/contracts/fixtures/valid_detection_validation_input.json "$private_dir/detection.local.json"
python3 -m cops engagement detection-validate \
  --input "$private_dir/detection.local.json" \
  --json-output "$private_dir/detection-report.local.json" \
  --markdown-output "$private_dir/detection-report.local.md"
python3 -m cops contract validate --type detection_validation_report "$private_dir/detection-report.local.json"
```

The command reads at most 4 MiB, creates new owner-only files, and prints no
report body. Keep the source and report in a private directory. The JSON retains
the action ID, expected telemetry, imported record IDs, action/search windows,
limits, and a next action for each result. Markdown shows signal counts, limits,
and next actions while omitting raw evidence payloads and source locators.
Review IDs and private files before sharing.
The saved report contract check verifies structure; it does not recompute the
classification from the private input. Retain that input when a result must be
audited or reproduced.

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
