# SOC Investigation Workbench playbook

## Purpose and audience

Use this playbook to investigate exported identity and alert records while preserving the distinction between a source observation and an analyst verdict. It is written for SOC analysts, incident responders, and reviewers who need a reproducible case record and shift handoff.

The workbench operates on local JSON. It does not query Microsoft Sentinel, execute KQL, call a provider API, contain an account, or decide whether activity is malicious or benign.

## Prerequisites

- Python 3.11 or later.
- A checkout of this repository.
- For a real case, authorized and redacted source exports that fall within one tenant, workspace, and UTC time window.
- A new output directory on a private, disposable filesystem. Do not store secrets, access tokens, raw credentials, or unnecessary personal data in case artifacts.

## Run the standalone demo

From an installed COPS environment, run the package demo through the stable dispatcher:

```bash
python3 -m cops demo soc-investigation-workbench
```

For reproducible local review, name an explicit output directory:

```bash
PACKAGE=plugins/detection-hunting/soc-investigation-workbench
OUT="${TMPDIR:-/tmp}/cops-soc-playback-$(date +%s)"
python3 "$PACKAGE/scripts/run_demo.py" --out-dir "$OUT"
```

The directory must not already exist. A successful run writes `playback-summary.json` with `status: passed` and creates `malicious`, `benign`, and `insufficient_evidence` subdirectories. See the [malicious-access walkthrough](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/investigate-malicious-access.md) for the expected decisions and files.

## Investigation data flow

1. **Intake** normalizes exported records, seeds account, IP, application, and resource entities, and creates unassessed evidence.
2. **Validate** checks the versioned case schema and cross-references before any decision step.
3. **Next** ranks eligible questions from the inquiry graph.
4. **Handoff** creates a bounded hunt request with the case scope, time window, hypothesis, and entity context.
5. **Evaluate** uses the offline vendored Sentinel fixture evaluator in the demo. A real analyst runs the query in an authorized service and records what happened.
6. **Import** adds an immutable result as an observation and records an analyst-supplied reason for each assessment.
7. **Revise** records a justified plan change when unavailable evidence leaves a step unresolved.
8. **Report and export** render the hypothesis state, reasons, gaps, and complete timeline for review or shift handoff.

## Artifact schema guide

| Artifact | Purpose | Key fields | Producer and consumer | Validation | Example |
| --- | --- | --- | --- | --- | --- |
| Case snapshot | Versioned investigation state | `case`, `scope`, `entities`, `evidence`, `hypotheses`, `steps`, `timeline` | `intake`; every later command | `investigate.py validate` checks schema and references | `malicious/case-intake.json` |
| Hunt handoff | Bounded request for one inquiry | case ID, step ID, hunt ID, surface, entity aliases, start, end | `handoff`; authorized analyst or hunt tool | Case and step must validate; scope is copied from the case | `malicious/handoff-H01.json` |
| Hunt result | Untrusted observation returned for import | evidence ID, outcome, summary, source, event time, assessments | fixture evaluator or analyst; `import` | Import validates required fields, IDs, and assessment references | `malicious/result-H01.json` |
| Evidence record | Immutable fact or failed collection attempt | `id`, `source`, `collected_at`, `event_time`, `entities`, `summary`, `assessments` | intake/import; reasoning and report commands | A reused ID must have identical content; hashes expose changes | entry in `case-final.json` |
| Assessment | Analyst interpretation of one evidence record | hypothesis ID, `supports` or `refutes`, reason | analyst result; hypothesis aggregation | Reason is required and the hypothesis must exist | H01 observation supports malicious activity because the synthetic sign-in violates the stated invariant |
| Report | Reviewable case state | hypothesis status, cited evidence, reasons, gaps, next steps | `report`; analyst or reviewer | Generated only from a valid snapshot | `malicious/final-report.json` |
| Handoff export | Portable JSON and Markdown case history | case scope, hypotheses, evidence hashes, gaps, timeline | `export-handoff`; next shift or reviewer | Export reads a valid snapshot and preserves the timeline | `malicious/handoff/` |
| Playback summary | Machine-readable acceptance result | schema version, status, evaluator limits, per-case assertions | `run_demo.py`; CI and maintainers | Demo exits nonzero if an expected intermediate or final state differs | `playback-summary.json` |

All examples in the table are under the output directory passed to `run_demo.py`.

## Make the analyst decision

Treat imported records as observations. Record an assessment only after the record gives a reason to support or refute a named hypothesis.

- **Malicious path:** H01 shows an anomalous sign-in pattern and H10 shows a suspicious consent pattern. The imported observations support the malicious hypothesis and refute the benign explanation.
- **Benign path:** The reference counterfactuals show activity consistent with the stated benign conditions. The observations refute malicious activity and support the benign explanation.
- **Insufficient-evidence path:** Fixture validation fails closed. Record the failed collection and the evidence gap. Do not convert missing, empty, or failed evidence into a benign assessment. Revise the plan with a reason and leave the hypotheses unresolved.

Before assigning a real disposition, review the source, scope, event time, entities, and reason for every assessment. Resolve contradictory evidence explicitly. If the available records cannot distinguish the hypotheses, preserve that uncertainty in the handoff.

## Failure, retry, and resume

Commands write a new snapshot or output directory. Keep the most recent valid snapshot and retry the failed command with a new output path. Do not edit an imported evidence record in place.

If collection fails, import a failed-closed result that describes the limitation, record a gap, and use `revise` to add or reprioritize a question. Resume by validating the last valid snapshot and running `next`; the case timeline retains the earlier attempt and reason for the plan change.

If the demo stops, inspect its last stderr message and delete only the disposable output directory you created, or choose another new directory. Re-running against an existing directory is rejected to prevent accidental overwrite.

## Troubleshooting

| Symptom | Meaning and action |
| --- | --- |
| Output directory already exists | Choose a new `--out-dir`. The demo will not overwrite prior evidence. |
| `vendor-lock.json` or snapshot verification fails | Do not bypass validation. A maintainer must resync from an allowlisted canonical or legacy Sentinel source and review the new lock and hashes. |
| H01 lacks an account or IP | Check that the intake exports contain supported account and network fields within the case scope. |
| H10 lacks an account or application | Check the Entra or consent export for a supported application identifier. H10 is independent of the H01 result. |
| No next step is eligible | Review completed steps, dependencies, evidence gaps, and the timeline. Use `revise` with a documented reason when the plan must change. |
| Evidence import is rejected | Validate the result schema and unique evidence ID. A prior ID cannot be reused with different content. |
| A failed or empty result appears benign | Remove the unsupported assessment, record an evidence gap, and leave the hypothesis unresolved. |

## Limitations

- The demo evaluator proves fixture contracts and reference invariants only. It does not parse or execute KQL and does not validate a live Sentinel workspace.
- Query entity aliases are context for the analyst; they are not guaranteed server-side filters.
- Synthetic fixtures do not establish coverage for a production tenant's schema, retention, identity model, or detection tuning.
- Reports summarize recorded evidence and reasons. They do not authorize containment or replace peer review.
- Local artifacts may still contain sensitive case data. Apply your organization's retention, access-control, and redaction requirements.

Run package-specific validation as described in the [verification guide](VERIFICATION.md).
