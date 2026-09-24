# Operations guide

## Safe local workflow

From the repository root:

```bash
python3 -m cops doctor
python3 -m cops info sentinel-hunt-workbench
python3 -m cops demo sentinel-hunt-workbench
python3 -m cops check sentinel-hunt-workbench
```

These commands use only local package data. The demo explains `H01`; it does not
run a query. The check validates the library, executes the deterministic synthetic
corpus, and verifies generated adapter hashes.

To render a proposal from this package directory:

```bash
python3 scripts/huntwb.py render H01 \
  --surface sentinel_analytics \
  --params examples/h01-parameters.json
```

Review the rendered query, scope markers, assumptions, expected evidence, and
stopping rules before using it. Do not paste secrets into parameter files or
commit tenant-specific values.

## Authorized live handoff

Before an analyst runs a rendered query against a service, the adopting
organization must independently confirm:

1. written authorization and the permitted tenant, workspaces, time range, and
   data sources;
2. current schema and surface compatibility;
3. privacy, retention, and data-residency requirements;
4. query cost, time bounds, and operational safety;
5. human review of the hypothesis, joins, confounders, and stopping rules; and
6. a plan to record actual service results without turning observations into
   unsupported efficacy claims.

The repository cannot satisfy those gates offline. A local pass must remain
labeled local. A failed or unavailable external check must remain failed or
unavailable.

## Release operations

1. Run `make check` without regenerating adapters. Resolve any drift.
2. Run `make release` to create deterministic local integrity evidence and the
   release report.
3. Verify that local gates pass and model, reviewer, or license evidence remains
   `pending` unless genuine content-addressed evidence was supplied.
4. Have two qualified reviewers inspect security, hunt quality, uncertainty
   language, residual risk, sources, and licensing.
5. Run the external 2,160-run host matrix under the evaluation protocol.
6. Rebuild the report against the exact same release-subject hash.
7. Before operational use, manually validate supported hunts in an authorized
   tenant, including schema, cost, latency, retention, and benign baselines.

`make release` writes `release/sentinel-hunt-workbench.zip`,
`release/package-validation.json`, `release/library-validation.json`,
`release/stress-test.json`, `release/compatibility.json`,
`release/local-evidence.json`, `release/release-report.json`, and four
content-addressed wrapper/payload pairs under `release/evidence/`. The local
envelope contains only integrity evidence. To recompute a report with genuine
external evidence, provide a complete `huntwb.external-evidence/v2` JSON
envelope containing the current subject hash and pointers to artifacts under
`release/evidence/`, then run:

```bash
python3 scripts/huntwb.py release-report --evidence /absolute/path/to/envelope.json
```

That command prints a report; review and retain the output with the exact
archive. Adding or editing any package source changes the subject hash and
invalidates earlier evidence. See `walkthrough.md` for artifact interpretation.

Never edit an evidence wrapper to turn a pending gate into a pass. Evidence
payloads and pointers are verified by digest, exact keys, subject hash, record
counts, and gate-specific semantics.
