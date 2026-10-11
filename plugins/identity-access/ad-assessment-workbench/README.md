# COPS AD Assessment Workbench

This package analyzes an explicitly scoped Active Directory inventory **offline**.
It accepts opaque IDs and evidence-linked directory or host relationship exports;
it does not connect to a domain controller or endpoint.

Run the synthetic demo with `python3 -m cops demo ad-assessment-workbench` and
the package gate with `python3 -m cops check ad-assessment-workbench`. To inspect
an approved local export from the source repository root, run
`python3 plugins/identity-access/ad-assessment-workbench/scripts/analyze.py <export.json>`.
From an installed package root, run `python3 scripts/analyze.py <export.json>`.
The input contract and limits are in `specs/ad-inventory-and-paths.md`.

The report's paths are structural candidates requiring validation. Every edge
shows collector ID, collection time, completeness, and observed/inferred support.
An exhausted search reports a path missing **from the collected graph**; a bounded
search that stops early reports `search_incomplete`. Incomplete or absent
forest/host collection remains partial or unknown. Live integration,
host installation, and privilege exercise are unverified.
