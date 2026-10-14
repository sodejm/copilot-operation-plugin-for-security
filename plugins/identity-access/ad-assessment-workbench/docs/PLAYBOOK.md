# AD Assessment Workbench playback

The manifest demo runs a complete, offline two-forest assessment. It validates the fixture, calculates collection coverage, traces bounded queries, writes a report, repeats the assessment, and confirms that duplicate JSON keys fail closed.

## Run and retain evidence

Run the registered manifest demo from the repository root:

```bash
python3 -m cops demo ad-assessment-workbench
```

To retain its artifacts, choose a path that does not exist:

```bash
python3 plugins/identity-access/ad-assessment-workbench/scripts/run_demo.py \
  --workspace /tmp/ad-playback-review
```

Omit `--workspace` for an automatically removed private temporary directory.

## Artifact layout

```text
ad-playback-review/
├── duplicate-key.json
├── expected-failure.txt
├── playback-summary.json
├── run-1/report.json
└── run-2/report.json
```

The reports must be byte-equivalent data after parsing. The summary is written only after the rerun and rejection checks pass.

## Semantic acceptance

The playback requires:

- two query results;
- one `candidate_paths` result containing a path;
- one `not_found_in_collected_graph` result;
- `inferred_relationship`, `partial_collection`, `protected_identity`, and `trust_boundary` flags on the candidate;
- an identical second report;
- rejection of duplicate JSON object keys.

Read `coverage` before interpreting a query. Follow `collector_id` from every path edge to the collection record and confirm collection time and completeness. Validate inferred edges and protected-identity handling outside this tool before proposing a change.

## Failures and reruns

Invalid files return a stable error code and exit status 2 through `scripts/analyze.py`. The validator rejects symlinks, oversized files, duplicate identifiers, broken references, out-of-scope objects, unsupported relations, malformed timestamps, and traversal inputs beyond package limits.

The demo refuses an existing workspace. Use a new directory for every retained rerun so that no stale report can satisfy review. The default mode deletes temporary output. Remove retained synthetic artifacts after review according to local evidence-retention rules.

## Limits

The playback uses a synthetic graph and no live service. It proves the bounded importer and analyzer behave as documented for that fixture. It cannot establish directory completeness, effective access, exploitability, attack activity, or production security.
