# Report export schemas

`source-anchor.schema.json` and `export-options.schema.json` describe the public
options accepted by `cops.reports.export_report`. Runtime validation also checks
that a full revision resolves to the exact Git commit, every path names UTF-8 text
in that commit, and every line range exists.

SARIF output targets the OASIS SARIF 2.1.0 schema published at
<https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json>.
The schema retrieved on 2026-10-15 has SHA-256
`ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25`.
It is not copied into the package; tests can validate against an independently
retrieved copy through `COPS_SARIF_SCHEMA_PATH`.
