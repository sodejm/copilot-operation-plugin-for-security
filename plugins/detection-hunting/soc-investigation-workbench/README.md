# SOC Investigation Workbench

SOC Investigation Workbench helps SOC analysts and incident responders build a local, evidence-backed case from exported security records. It preserves competing hypotheses, ranks the next investigative step, creates bounded hunt handoffs, imports immutable observations, and produces reviewable reports. It never queries a live service or assigns an analyst verdict.

## Run the complete playback

Use Python 3.11 or later from the repository root. No tenant credentials or network access are required.

```bash
PACKAGE=plugins/detection-hunting/soc-investigation-workbench
OUT="${TMPDIR:-/tmp}/cops-soc-playback-$(date +%s)"
python3 "$PACKAGE/scripts/run_demo.py" --out-dir "$OUT"
cat "$OUT/playback-summary.json"
```

The output directory must not already exist. The script creates it with owner-only permissions and exercises three cases over the same synthetic tenant, workspace, entities, and UTC time window:

- `malicious`: imports supporting H01 and H10 observations and ends with a supported malicious-activity hypothesis.
- `benign`: imports counterfactual observations that refute malicious activity and support a benign explanation.
- `insufficient_evidence`: imports failed-closed observations, records evidence gaps, revises the pending plan, and leaves both hypotheses unresolved.

Omit `--out-dir` for a transient qualification run. The script creates an owner-only temporary directory, removes it after either success or failure, and returns the three-case assessment as `playback_summary` without reporting its path. Pass an explicit new `--out-dir` when you need to retain and inspect the generated artifacts.

Each path executes intake, validation, next-step selection, hunt handoff, fixture evaluation, immutable evidence import, report generation, and timeline export. Success means the script checked every intermediate and final assertion. The vendored evaluator checks reference fixture semantics; it does not execute Kusto Query Language (KQL) or contact Microsoft Sentinel.

For a guided investigation, see the [malicious-access walkthrough](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/investigate-malicious-access.md). For operations and recovery, use the [analyst playbook](docs/PLAYBOOK.md). For package gates and vendor integrity, use the [verification guide](docs/VERIFICATION.md).

## Manual workflow

Start a case from local exports:

```bash
python3 plugins/detection-hunting/soc-investigation-workbench/scripts/investigate.py intake \
  --case-id incident-402 \
  --tenant tenant-a \
  --workspace workspace-a \
  --start 2026-01-01T00:00:00Z \
  --end 2026-01-02T00:00:00Z \
  --sources sentinel:plugins/detection-hunting/soc-investigation-workbench/examples/intake/sentinel-incidents.json \
            splunk:plugins/detection-hunting/soc-investigation-workbench/examples/intake/splunk-events.json \
            entra:plugins/detection-hunting/soc-investigation-workbench/examples/intake/entra-signins.json \
  --out /tmp/incident-402.json
python3 plugins/detection-hunting/soc-investigation-workbench/scripts/investigate.py validate /tmp/incident-402.json
python3 plugins/detection-hunting/soc-investigation-workbench/scripts/investigate.py next /tmp/incident-402.json
python3 plugins/detection-hunting/soc-investigation-workbench/scripts/investigate.py handoff \
  /tmp/incident-402.json --step signin-triage > /tmp/incident-402-h01.json
```

The initial evidence is deliberately unassessed. Source severity, risk labels, error codes, and successful actions are observations; an analyst must supply a reasoned assessment after reviewing relevant evidence. Empty or failed evidence cannot establish a benign outcome.

The H01 sign-in handoff carries the account and IP context. The independent H10 consent handoff carries the account and application context. Query aliases supply investigation context and do not promise server-side entity filtering.

## Design and data flow

The workbench treats the case snapshot as the single versioned state object. Commands read one validated snapshot and write a new file; evidence imports preserve content hashes and reject conflicting reuse of an evidence ID. Handoffs carry the case scope and question to another tool without embedding credentials. Reports and exports present recorded observations, assessments, reasons, gaps, and the full timeline.

| Contract or artifact | Purpose | Key fields | Producer | Consumer | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- |
| Case snapshot | Preserve scoped investigation state and competing hypotheses | Case, tenant, workspace, time window, entities, hypotheses, evidence gaps | Intake and subsequent case commands | Every workbench command and analyst | Versioned schema, scope checks, and immutable evidence identifiers | `incident-402` with H01 and H10 pending |
| Hunt handoff | Ask a bounded question using case context | Step ID, hunt ID, scope, entities, question | `next` and `handoff` commands | Vendored hunt evaluator or another approved tool | Hunt and scope compatibility checks | H01 sign-in triage for one account and IP |
| Evidence observation | Import a content-addressed result without assigning a verdict | Evidence ID, source, status, observations, SHA-256 | Fixture evaluator or analyst import | Hypothesis assessment and report generation | Hash verification and conflicting-ID rejection | H10 consent observation supporting malicious activity |
| Report and timeline | Present recorded facts, assessments, gaps, and chronology | Hypothesis status, rationale, evidence references, timeline entries | Reporting commands | Analyst and incident reviewer | Snapshot validation and evidence-reference integrity | Insufficient-evidence report with both hypotheses unresolved |
| Playback summary | Qualify all three synthetic paths | Case outcomes, step counts, artifact paths, assertions | `scripts/run_demo.py` | Maintainer | Semantic assertions for malicious, benign, and failed-closed cases | `malicious` ends with a supported hypothesis |

The Sentinel hunt catalog is a verified vendored snapshot. `vendor-lock.json` records its canonical source path, base revision, file hashes, snapshot hash, and license. Package validation fails closed when the snapshot is absent, modified, or inconsistent with the lock.

## Package validation

```bash
python3 plugins/detection-hunting/soc-investigation-workbench/scripts/validate-package.py
python3 -m pytest -q tests/step_defs/test_soc_investigation.py
```

The package is offered under the [PolyForm Noncommercial License 1.0.0](LICENSE).
