# Detection Quality & Regression Workbench Specification

## Goal and evidence boundary

The workbench evaluates versioned KQL and SPL rule contracts against labeled,
synthetic fixture cases. It reports static dependencies, per-case outcomes, and
precision and recall over evaluable cases. It does not parse, compile, or run KQL
or SPL in a native provider engine and does not establish production alert rates.

## Inputs and result contract

- Every rule document has a matching fixture document with the same basename.
- A fixture suite contains at least one case; an empty suite is invalid.
- Cases declare an expected match or schema error. Missing required fields must
  produce a `missing_field_error`, rather than silently becoming a benign result.
- JSON reports use `cops.detection-quality-report/v2` and preserve the rule,
  static analysis, metrics, and case results. Markdown reports are derived review
  views of those JSON results.
- A test-suite command rejects empty rule directories, empty fixture directories,
  and unmatched rule or fixture basenames.

## Offline playback contract

`python3 -m cops demo detection-quality-workbench` invokes the package playback
runner. By default, it creates a mode-`0700` temporary output directory;
`scripts/run_demo.py --out-dir <directory>` retains the same artifacts in an
operator-selected private directory.

The playback must:

1. Discover the exact packaged rule and fixture pairs and reject an empty,
   missing, extra, or mismatched set.
2. Evaluate every pair and require each platform to exercise a true positive,
   true negative, and schema-error path, including an actual
   `missing_field_error`.
3. Require zero false positives and zero false negatives.
4. Write and parse versioned JSON reports, require nonempty paired Markdown
   reports, and write `cops.detection-quality-playback/v1`
   `playback-summary.json`.
5. Repeat evaluation and require an equivalent result.

Missing or malformed inputs, missing required behavior, false positives or false
negatives, missing or empty reports, and rerun differences must exit nonzero.
Partial output is diagnostic evidence; after correction, rerun the complete
command.

## Acceptance evidence

- `tests/test_detection_quality_playback.py` covers the successful packaged
  workflow, intermediate and final artifacts, deterministic reruns, and a missing
  fixture failure.
- Package unit tests cover evaluator outcomes, schema errors, and command behavior.
- `python3 -m cops check detection-quality-workbench` runs package validation.

The playback validates offline reference predicates and report contracts. Native
KQL and SPL syntax, planner behavior, workspace or index schemas, provider
authentication, and production execution require separate authorized integration
evidence.
