# Entra Identity Workbench playback

This playbook exercises the complete offline workflow with the checked-in `contoso-corp` fixture: manifest intake, checksum validation, graph construction, hypothesis analysis, cross-field freshness and provenance validation, report rendering, deterministic rerun, and invalid-manifest rejection.

## Run the playback

Run the registered manifest demo from the repository root:

```bash
python3 -m cops demo entra-identity-workbench
```

Use a path that does not exist because the script deliberately refuses an existing workspace:

```bash
python3 plugins/identity-access/entra-identity-workbench/scripts/run_demo.py \
  --workspace /tmp/entra-playback-review
```

Without `--workspace`, the script uses and removes a private temporary directory automatically.

## Artifact layout

```text
entra-playback-review/
├── expected-failure.json
├── expected-failure.txt
├── playback-summary.json
├── run-1/
│   ├── graph.json
│   ├── report.json
│   └── report.md
└── run-2/
    ├── graph.json
    ├── report.json
    └── report.md
```

`graph.json` is the intermediate assessment model. `report.json` is the durable machine-readable result, and `report.md` is its analyst view. The second run must match the first after excluding the report generation timestamp.

## Acceptance checks

A successful exit means the script verified all of the following:

- all source hashes in the manifest matched;
- graph and report artifacts passed cross-field freshness and provenance validation;
- the graph contained 18 nodes and 13 edges;
- the report contained 7 nonempty hypotheses;
- a second assessment was semantically equivalent;
- an empty manifest failed and did not produce a valid assessment.

Inspect `source_coverage` before interpreting a hypothesis. Trace its evidence references into `graph.json`; treat stale or missing sources as unresolved evidence, not a negative finding.

## Failures, reruns, and cleanup

Manifest shape, unsafe paths, hash mismatches, unsupported source types, and invalid artifacts fail closed. The retained `expected-failure.txt` records the rejected-input exception class without including sensitive content.

For a rerun, use a new workspace or delete a disposable workspace after review. Never merge files from two runs. Remove retained synthetic output with your normal temporary-file cleanup process; the default mode cleans itself.

## Production use limits

Replace the fixture only with an authorized, local export and preserve its manifest and hashes with the assessment record. This playback proves the offline pipeline works for the synthetic contract. It does not prove live Microsoft integration, production export completeness, exploitability, or tenant security.

<!-- BEGIN COPS GENERATED OFFLINE ASSESSMENT LINKS -->
## Generated offline assessment

- [Machine-readable playbook](../playbooks/offline-assessment.json)
- [Runnable offline walkthrough](../walkthroughs/offline-assessment.md)
<!-- END COPS GENERATED OFFLINE ASSESSMENT LINKS -->
