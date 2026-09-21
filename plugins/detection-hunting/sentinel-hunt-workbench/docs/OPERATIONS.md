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

Run `release-report` only with real evidence documents bound to the exact release
subject. Missing model-host evaluation, two distinct human approvals, license
review, or integrity evidence yields `qualification_withheld`. Never create dummy
approvals to make a release pass.
