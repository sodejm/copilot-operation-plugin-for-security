# Offline release walkthrough

Start in the `sentinel-hunt-workbench` directory. Run `make check` to validate
the complete package, canonical adapters, unit/CLI behavior, and synthetic
reference corpus. This path uses only Python's standard library and never
connects to a tenant or executes KQL in a Kusto engine.

Run `make release` to build the archive and local release evidence. The archive
is `release/sentinel-hunt-workbench.zip`. Its bytes are reproducible from the
same source inputs because file order, timestamps, permissions, and compression
method are fixed. `release/local-evidence.json` points to the local integrity
index. Each wrapper and payload under `release/evidence/` is verified by SHA-256
and bound to `release_subject.sha256` in `release/release-report.json`.

The release directory also contains `package-validation.json`,
`library-validation.json`, `stress-test.json`, and `compatibility.json` for
reviewing the exact local results behind the report.

The generated CycloneDX document inventories package files; the provenance
manifest maps each source path to its hash and identifies the archive hash.
The bounded secret scan searches for common private-key and token shapes and
records only finding classes and paths. A passing result does not replace a
human security review. The reproducible-build evidence records two identical
archive builds from one exact subject.

Review `release/release-report.json` before using any status label. The
deterministic contract, fixture, adapter, and release-integrity gates can pass
locally. Model-host evaluation, two human approvals, and license review remain
pending until actual artifacts are supplied. A withheld overall qualification
is expected at that point. The report explicitly records Kusto parsing/engine
and Microsoft-service execution as unavailable or unperformed.

For a separate genuine external evidence envelope, follow
`evaluations/EVALUATION_PROTOCOL.md` and `schemas/external-evidence.schema.json`.
Do not edit wrappers to assert an unperformed run. Every external artifact must
bind to the unchanged release-subject hash. Tenant behavior, cost, latency,
retention, efficacy, and false-positive performance require independent,
authorized operational validation.
