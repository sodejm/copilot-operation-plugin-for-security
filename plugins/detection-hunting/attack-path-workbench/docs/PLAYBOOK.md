# Attack Path Workbench playback

The manifest demo executes the illustrative workflow end to end: input validation, record intake, graph normalization, path analysis, report-set completion, deterministic rerun, Wiz query blocking, and invalid-input rejection.

## Run and retain evidence

Run the registered manifest demo from the repository root:

```bash
python3 -m cops demo attack-path-workbench
```

To retain its artifacts, use a path that does not exist:

```bash
python3 plugins/detection-hunting/attack-path-workbench/scripts/run_demo.py \
  --workspace /tmp/attack-path-playback-review
```

Omit `--workspace` to use an automatically removed private temporary directory.

## Artifact layout

```text
attack-path-playback-review/
├── invalid-input.json
├── playback-summary.json
├── wiz-query-intent.json
├── run-1/
│   ├── completion.json
│   ├── graph.json
│   ├── report.json
│   └── additional report-set artifacts
└── run-2/
    └── the same completed report set
```

`completion.json` lists the expected report files and their SHA-256 digests. Its presence means the full set was written and validated; the playback recomputes every listed digest.

## Semantic acceptance

A successful run verifies:

- the graph has nodes and edges;
- the report contains one supported path and one candidate path;
- quarantine and graph-exclusion records are retained;
- attack-flow rendering is marked `pending_reference_bundle`;
- every completion hash matches its file;
- the complete report is identical on rerun;
- Wiz query rendering remains `blocked_pending_docs`;
- invalid input returns status 2 and produces no completion manifest.

Review coverage, quarantine, and exclusions first. Trace every supported edge to evidence. Treat a candidate path as a hypothesis requiring the report's stated follow-up. Do not treat excluded evidence as proof that the relationship is absent.

## Failures, reruns, and cleanup

Input or output schema failures stop the CLI and omit `completion.json`, so incomplete directories cannot be mistaken for completed report sets. The demo refuses an existing workspace. Use a new directory for every retained run and compare the completion manifests and reports.

The default demo cleans its temporary workspace. Remove retained synthetic directories after review according to local evidence-retention rules.

## Vendor and production limits

The demo uses only the synthetic illustrative adapter. `wiz-query-intent.json` records why query rendering did not occur; it is not an executable query. Do not relabel the illustrative schema as vendor evidence. Passing the playback does not demonstrate live Wiz or Azure integration, full production graph coverage, exploitability, attacker activity, or business impact.
