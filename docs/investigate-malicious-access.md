---
layout: documentation
title: "Investigate Malicious Access"
description: "Run an offline SOC investigation from synthetic intake through evidence review, plan revision, and handoff."
---

# Investigate malicious access with the SOC workbench

This walkthrough exercises a complete offline investigation and shows how the same evidence workflow reaches malicious, benign, and insufficient-evidence outcomes. It is intended for SOC analysts learning the case model and maintainers reviewing the package contract.

The journey uses synthetic data for `tenant-a` and `workspace-a` from `2026-01-01T00:00:00Z` through `2026-01-02T00:00:00Z`. H01 examines the same account and source IP across sign-ins. H10 examines that account and an application consent. No live query runs, and no credentials are required.

## Run the journey

From the repository root, create a new private output path and run:

```bash
PACKAGE=plugins/detection-hunting/soc-investigation-workbench
OUT="${TMPDIR:-/tmp}/cops-soc-playback-$(date +%s)"
python3 "$PACKAGE/scripts/run_demo.py" --out-dir "$OUT"
```

The command exits with a nonzero status when an intermediate or final assertion fails. On success, inspect the top-level result:

```bash
python3 -m json.tool "$OUT/playback-summary.json"
```

The summary identifies the evaluator as offline and reference-invariant, records that live service validation was not performed, and reports all three cases as passed.

## Run each CLI step

The complete playback creates synthetic observations that you can reuse to walk through each command individually. Keep both output directories private and disposable:

```bash
CLI="$PACKAGE/scripts/investigate.py"
MANUAL="${TMPDIR:-/tmp}/cops-soc-manual-$(date +%s)"
EVALUATION="${TMPDIR:-/tmp}/cops-sentinel-evaluation-$(date +%s)"
umask 077
mkdir "$MANUAL"
```

Create an unassessed case from the synthetic Entra export, validate it, and inspect the eligible inquiries:

```bash
python3 "$CLI" intake \
  --case-id case-malicious-access-manual \
  --tenant tenant-a \
  --workspace workspace-a \
  --start 2026-01-01T00:00:00Z \
  --end 2026-01-02T00:00:00Z \
  --sources "entra:$PACKAGE/examples/intake/entra-signins.json" \
  --out "$MANUAL/01-intake.json"
python3 "$CLI" validate "$MANUAL/01-intake.json"
python3 "$CLI" next "$MANUAL/01-intake.json"
```

Generate the H01 sign-in handoff. Its entity aliases must identify an account and an IP address:

```bash
python3 "$CLI" handoff "$MANUAL/01-intake.json" --step signin-triage \
  > "$MANUAL/handoff-H01.json"
python3 -m json.tool "$MANUAL/handoff-H01.json"
```

Run the vendored offline evaluator and inspect its malicious H01 result:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 "$PACKAGE/vendor/sentinel-hunt-workbench/scripts/run_demo.py" \
  --out-dir "$EVALUATION"
python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(json.dumps(x["hunts"]["H01"]["malicious"], indent=2))' \
  "$EVALUATION/evaluation-summary.json"
```

The evaluator checks the fixture contract and reference invariants. It does not execute Kusto Query Language (KQL) or contact Microsoft Sentinel. Import the corresponding synthetic observation produced by the complete playback:

```bash
python3 "$CLI" import \
  "$MANUAL/01-intake.json" \
  "$OUT/malicious/02-h01-observation.json" \
  --out "$MANUAL/02-after-H01.json"
```

Generate the independent H10 consent handoff, inspect the evaluator result, and import the synthetic observation. The handoff must identify the account and application even though H01 is already complete:

```bash
python3 "$CLI" handoff "$MANUAL/02-after-H01.json" --step token-audit \
  > "$MANUAL/handoff-H10.json"
python3 -m json.tool "$MANUAL/handoff-H10.json"
python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(json.dumps(x["hunts"]["H10"]["malicious"], indent=2))' \
  "$EVALUATION/evaluation-summary.json"
python3 "$CLI" import \
  "$MANUAL/02-after-H01.json" \
  "$OUT/malicious/03-h10-observation.json" \
  --out "$MANUAL/03-after-H10.json"
```

Create the analyst report and export the complete handoff timeline:

```bash
python3 "$CLI" report "$MANUAL/03-after-H10.json" \
  > "$MANUAL/final-report.json"
python3 "$CLI" export-handoff "$MANUAL/03-after-H10.json" \
  --out-dir "$MANUAL/handoff-export"
python3 -m json.tool "$MANUAL/final-report.json"
cat "$MANUAL/handoff-export/handoff.md"
```

The insufficient-evidence playback also produces a justified revised plan. Apply it to the immutable snapshot after the failed H01 observation, then validate and resume:

```bash
python3 "$CLI" revise \
  "$OUT/insufficient_evidence/02-case-after-h01.json" \
  "$OUT/insufficient_evidence/03-revised-steps.json" \
  --out "$MANUAL/insufficient-revised.json"
python3 "$CLI" validate "$MANUAL/insufficient-revised.json"
python3 "$CLI" next "$MANUAL/insufficient-revised.json"
```

The final command must return H10 as the remaining independent inquiry. The failed H01 collection remains a coverage gap and does not count as evidence for the benign hypothesis.

## Follow the evidence path

For each case, the playback performs these steps:

1. Intake normalizes the synthetic Entra export into an unassessed case. Source severity and risk labels remain observations.
2. Validation checks the case schema, entity references, hypothesis graph, and UTC scope.
3. `next` selects the sign-in inquiry.
4. The H01 handoff includes account and IP context for the fixed time window.
5. The vendored Sentinel evaluator checks the synthetic fixture's reference invariants or rejects its invalid input contract.
6. Import records that outcome as immutable evidence with an explicit assessment reason, or records a failed-closed evidence gap.
7. The H10 handoff independently includes account and application context. It does not depend on H01 succeeding.
8. Report and export commands preserve the evidence, reasons, unresolved gaps, and complete timeline.

The three cases differ only in what the controlled fixture observations establish:

| Case | H01 and H10 observations | Expected hypothesis state | Required analyst action |
| --- | --- | --- | --- |
| `malicious` | Both match their true-positive reference invariants | Malicious supported; benign refuted | Cite both observations and their reasons before escalation |
| `benign` | Both satisfy their benign counterfactuals | Malicious refuted; benign supported | Confirm the benign conditions apply to the real scope before closure |
| `insufficient_evidence` | Fixture validation fails closed | Both unresolved | Record gaps, revise the plan, and collect another independent source |

An empty result, collection error, schema mismatch, or unavailable source does not support a benign verdict. The insufficient-evidence path verifies this rule by keeping both hypotheses unresolved after a justified plan revision.

## Inspect the artifacts

Use these commands after the playback succeeds:

```bash
python3 -m json.tool "$OUT/malicious/handoff-H01.json"
python3 -m json.tool "$OUT/malicious/handoff-H10.json"
python3 -m json.tool "$OUT/malicious/03-case-after-h10.json"
python3 -m json.tool "$OUT/malicious/final-report.json"
python3 -m json.tool "$OUT/insufficient_evidence/final-report.json"
cat "$OUT/malicious/handoff-export/handoff.md"
```

Confirm that:

- Intake evidence has no preassigned assessment.
- H01 has account and IP entity aliases.
- H10 has account and application entity aliases and remains independently eligible.
- Every supporting or refuting assessment names a hypothesis and gives a reason.
- The insufficient-evidence report names the failed collection and remaining gap without a benign verdict.
- The exported handoff contains the complete case timeline.

## Continue with an authorized case

For a real investigation, replace the synthetic intake exports with authorized, redacted exports and run the same sequence through `scripts/investigate.py`. Execute the generated hunt request only in an authorized service. Import the observed result with its source, event time, entity links, and analyst reasoning.

Preserve the last valid snapshot if a command or collection fails. Record the limitation, revise the plan with a reason, validate the revised snapshot, and resume with `next`. Do not edit previously imported evidence in place.

See the package [analyst playbook](../plugins/detection-hunting/soc-investigation-workbench/docs/PLAYBOOK.md) for the artifact schema, command boundaries, recovery guidance, and limitations. See the package [verification guide](../plugins/detection-hunting/soc-investigation-workbench/docs/VERIFICATION.md) for vendor and release checks.
