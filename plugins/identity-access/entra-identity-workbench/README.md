# COPS Entra Identity Workbench

The Entra Identity Workbench turns a checksummed, offline tenant export into an identity graph and a set of evidence-linked exposure hypotheses. It models people, applications, service principals, managed identities, AI agents, groups, roles, resources, credentials, and relationship edges without contacting Microsoft Graph or Azure Resource Manager.

Use the results to decide what an analyst should validate next. A graph path or hypothesis shows structural reachability in the supplied export. It does not prove that an attacker exercised the path, that a credential is usable, or that the export covers the production tenant.

## Prerequisites and quick start

Run from the repository root with Python 3.11 or later. The package has no network prerequisite.

```bash
python3 plugins/identity-access/entra-identity-workbench/scripts/run_demo.py
```

The manifest `demo.command` runs the same playback through `$PYTHON`. To retain its artifacts for inspection, provide a new directory:

```bash
python3 plugins/identity-access/entra-identity-workbench/scripts/run_demo.py \
  --workspace /tmp/entra-playback
```

The playback refuses an existing workspace so that a prior report cannot be mistaken for current output.

For a separate export, create a manifest conforming to `schemas/manifest.schema.json`, include the declared SHA-256 for every source file, and use the package modules as shown in `scripts/run_demo.py`. See [the playbook](docs/PLAYBOOK.md) for the operational sequence and [the verification guide](docs/VERIFICATION.md) for package checks.

## Preparing a private export

An authorized collector must obtain the tenant data separately. Grant that collector only the read permissions needed for the selected sources and tenant; this offline package requests no Microsoft Graph permissions and cannot confirm the collector's effective rights or whether pagination completed. Record the collector's permitted tenant, source set, collection time, and any gaps outside the report. A missing source or an incomplete collection must not be represented as full coverage.

Exports can contain names, user principal names, application identifiers, and relationship details. Remove secrets and unnecessary personal data before ingestion, and replace identifiers consistently across source files so graph joins still work. The workbench does not automatically redact input or output. Recompute each manifest SHA-256 after sanitizing, keep the source bundle and generated graph and reports in access-controlled storage, and apply the engagement's retention and deletion rules. Do not commit real tenant exports or reports.

Set each source's `exported_at` to its actual collection time; if omitted, the manifest-level `exported_at` is used. The assessment uses a 24-hour window measured from its UTC `assessed_at`. Only an available, fully collected source with a valid timestamp inside that window is `fresh`. Missing, partial, future-dated, invalid-time, and older sources are `unknown` with a reason in `source_coverage`. Their nodes and edges are not current evidence for a hypothesis. A hash match proves file integrity relative to the manifest, not collection completeness or freshness.

## Design and data flow

1. **Intake:** `ingest_tenant_export` validates the manifest, confines source paths to the manifest directory, verifies hashes, and parses the declared sources.
2. **Graph construction:** `build_identity_graph` normalizes identities and relationships and records source coverage and freshness.
3. **Assessment:** `analyze_identity_graph` derives bounded exposure hypotheses from observed graph structure.
4. **Reporting:** JSON and Markdown renderers produce a machine-readable report and a review copy. Freshness and provenance cross-field checks run before playback succeeds.

No stage enriches missing evidence with a live lookup. Missing, stale, or incomplete sources remain coverage limits in the output.

## Contracts and artifacts

| Contract or artifact | Purpose | Key fields | Producer and consumer | Definition and validation |
| --- | --- | --- | --- | --- |
| Export manifest | Binds one tenant export to named, hashed source files | `schema_version`, `tenant_id`, `exported_at`, `sources` | Export preparer → ingestion | `schemas/manifest.schema.json`; structural checks plus file SHA-256 verification |
| Identity graph | Normalized evidence for structural traversal | `tenant_id`, `assessed_at`, `source_coverage`, `nodes`, `edges` | Graph builder → analyzer and reviewer | `schemas/graph.v2.schema.json`; `validate_graph_artifact` |
| Exposure report | Prioritized review hypotheses with evidence and caveats | `summary`, `source_coverage`, `hypotheses` | Analyzer → JSON/Markdown renderer and analyst | `schemas/report.v2.schema.json`; `validate_report_artifact` |
| `report.md` | Human review view of the JSON report | Summary, coverage, hypotheses | Renderer → analyst | Derived from the validated in-memory graph and hypotheses |
| `playback-summary.json` | Retained playback acceptance result | counts, rerun result, expected-failure result | Demo → package validator or reviewer | Written only after semantic assertions pass |

The original `graph.schema.json` and `report.schema.json` retain the v1 contract for historical artifacts. Current exports use v2 and require assessment time and complete source coverage; consumers should select the schema from `schema_version`.

## Reading the output

Start with `source_coverage`; it determines how broadly any hypothesis can be read. Review each hypothesis's evidence and uncertainty before considering remediation. The included fixture produces 18 nodes, 13 edges, and 7 hypotheses. Those numbers are regression expectations for synthetic data, not production benchmarks.

The package is offline and read-only. It does not validate live permissions, credential viability, conditional-access enforcement, exploitability, or complete tenant coverage. A clean report cannot establish that a tenant is secure.
