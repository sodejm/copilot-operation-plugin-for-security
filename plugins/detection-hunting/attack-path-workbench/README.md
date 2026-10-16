# COPS Attack Path Workbench

The Attack Path Workbench converts approved, offline evidence into a reviewable graph, separates supported from candidate paths, and preserves quarantined records and graph exclusions. The current manifest demo uses the package's illustrative export contract to show the complete intake-to-report workflow.

The illustrative contract is not a Wiz mapping. Wiz query rendering remains blocked until approved local documentation defines the fields and semantics. A path in the report describes relationships in supplied evidence; it does not prove exploitation, attacker activity, or complete production coverage.

## Prerequisites and quick start

Run from the repository root with Python 3.11 or later:

```bash
python3 -m cops demo attack-path-workbench
```

The public command creates an owner-only temporary workspace, verifies the
playback, and removes the workspace. Use the package runner directly when you
need to retain the reports and rejection evidence. Both direct commands require
their final output directory not to exist. Create a private scratch parent so
each invocation gets a new destination:

```bash
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cops-attack-path.XXXXXX")"
chmod 700 "$scratch"
python3 plugins/detection-hunting/attack-path-workbench/scripts/run_demo.py \
  --workspace "$scratch/playback"
```

The CLI used by the playback is also available directly:

```bash
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cops-attack-path.XXXXXX")"
chmod 700 "$scratch"
python3 plugins/detection-hunting/attack-path-workbench/scripts/attackpath.py \
  analyze plugins/detection-hunting/attack-path-workbench/fixtures/illustrative/input.json \
  --output-dir "$scratch/report"
```

Each example prints or retains its artifacts below the unique scratch parent.
Remove that parent after review.

See [the playbook](docs/PLAYBOOK.md) before applying the workflow to other authorized evidence and [the verification guide](docs/VERIFICATION.md) for package checks.

## Design and data flow

1. The input manifest declares context and one or more local sources.
2. Intake validates source type and content; unusable records are quarantined instead of silently entering the graph.
3. Normalization creates graph nodes and edges and records excluded evidence.
4. Path analysis separates fully supported paths from candidates that need validation.
5. Reporting emits graph, evidence, coverage, actions, JSON/Markdown reports, and a completion manifest containing artifact hashes.
6. A query-intent helper can describe a requested Wiz query, but rendering fails closed with `blocked_pending_docs`.

## Contracts and artifacts

| Contract or artifact | Purpose | Key fields | Producer and consumer | Definition and validation |
| --- | --- | --- | --- | --- |
| Input manifest | Selects local sources and assessment context | `schema_version`, `sources`, `context` | Evidence preparer → CLI | `schemas/input-v1.schema.json` |
| Illustrative export | Supplies synthetic canonical records | `schema_version`, `records` | Fixture → illustrative adapter | `schemas/illustrative-export-v1.schema.json`; explicitly not a vendor field mapping |
| `graph.json` | Exposes normalized nodes and edges for review | nodes, edges, evidence references | Normalizer → path analyzer and analyst | Output records contract in `schemas/records-v1.schema.json` |
| `report.json` | Holds coverage, evidence, supported/candidate paths, exclusions, and actions | `coverage`, `graph`, `quarantine`, `supported_paths`, `candidate_paths`, `attack_flow` | Analyzer → reviewer | `schemas/report-v2.schema.json` |
| `completion.json` | Binds the completed report set to one run | `run_id`, `status`, `files` | Reporter → downstream verifier | `schemas/completion-v1.schema.json`; SHA-256 checked by the playback |
| `wiz-query-intent.json` | Records the unrendered vendor query request and blocker | requested identifiers, `render_status` | Query helper → reviewer | Must remain `blocked_pending_docs` without approved documentation |

## Reading the report

Review coverage, quarantine, and graph exclusions before paths. A supported path has evidence for each included relationship. A candidate path requires the stated validation. The synthetic playback expects one of each and confirms the completion hashes.

The package also contains separately versioned Azure contracts. Their presence does not turn the illustrative demo into live Azure or Wiz coverage. Synthetic success cannot establish production reachability, exploitability, business impact, or security.
