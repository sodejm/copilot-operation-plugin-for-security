# AI Export Privacy Boundary

## Status and scope

`cops.evidence.export_policy.ExportBoundary` is a reusable, local, fail-closed
boundary for a copy of structured evidence, a bounded text stream, and a small
set of text attachments before an adapter delivers that copy to a declared
sink. Its v1 policy shape is described by
[`cops/contracts/export_policy_v1.schema.json`](../cops/contracts/export_policy_v1.schema.json)
and is parsed by `ExportPolicy.from_mapping`.

This is not universal data-loss prevention, anonymization, or a provider
retention guarantee. It does not retain raw input, implement a raw-data
fallback, or quarantine refused content. An adapter must call the boundary for
each export; sharing an evidence object does not automatically apply it.

## Supported sink matrix

| Destination | Stable v1 contract | Production path instrumented in this revision | Test coverage |
| --- | --- | --- | --- |
| `model_provider` | `cops.evidence.export_provider_assessment` accepts only a `model_provider` sink descriptor and an exact registered `(sink_id, destination, purpose)` tuple. | It derives a local assessment and calls the boundary immediately before a caller-provided sink. The repository does not implement a provider recipient or network client. | A synthetic envelope/receipt test transforms content and a text attachment before an `assessment-provider-fixture` fake sink; a wrong destination refuses before delivery. |
| `telemetry` | `cops.evidence.export_assessment_telemetry` accepts only a `telemetry` sink descriptor and an exact registered tuple. | It derives a local assessment and calls the boundary immediately before a caller-provided sink. The repository does not implement a telemetry backend or network client. | A synthetic envelope/receipt test transforms content before an `assessment-telemetry-fixture` fake sink; a wrong destination refuses before delivery. |
| `report` | `cops.evidence.export_assessment_report` and `cops.evidence.export_langsmith_inventory` accept only a `report` sink descriptor and an exact registered tuple. | The assessment adapter derives a local assessment with `report()`. The LangSmith adapter derives a bounded inventory report from an engagement-scoped snapshot. Each calls `ExportBoundary.export` immediately before the caller-provided sink; neither selects a recipient or makes a network request. | Synthetic tests exercise both adapters with registered fake sinks, transformed fields and refusal; `fixture-report` also exercises bounded text attachments. |
| `diagnostic` | A policy may register an exact tuple. | `cops.diagnostics.export_diagnostic_report` transforms a `DiagnosticReport` immediately before the caller-provided sink. `command_diagnostics` still renders only local terminal output; the repository does not implement a diagnostic recipient backend. | A synthetic `DiagnosticReport` test proves redaction and omission before a fake sink; `fixture-diagnostic` exercises safe audit output. |

`export_provider_assessment`, `export_assessment_telemetry`,
`export_assessment_report`, `export_langsmith_inventory`, and
`export_diagnostic_report` are the integrated offline contract adapters in this
revision. Each accepts a caller-provided typed
sink and refuses a descriptor for a different destination before transforming
or sending. The first three transform the same locally derived assessment copy;
the telemetry path does not imply that the repository produces a distinct
telemetry event. The diagnostic path transforms a real `DiagnosticReport`.
Neither proves provider, telemetry, report-recipient, or diagnostic-recipient
delivery behavior or retention. The fixture sink IDs are test-only declarations
and do not configure any backend. An additional concrete adapter must declare its
real stable sink ID, destination and purpose in a reviewed policy, then call
this boundary immediately before the one send operation.

## Contract

`ExportBoundary.export(sink, payload, *, text_chunks, attachments,
restricted_evidence_reference, pseudonym_scope)` builds one `SanitizedExport`
and only then calls `sink.send`. `sink.descriptor` must exactly match a
registered `DestinationRule`; unregistered destinations refuse before the sink
is called. Source and sink failures produce generic `ExportRefused` values
without chained source exception text. The boundary does not retry or fall back
to raw content; a caller may retry by invoking the boundary again. Cancellation
propagates without delivery.

Field rules are an allowlist. Each path has a classification and action:
`allow`, `redact`, `omit`, or `pseudonymize`. Unknown structured fields are
omitted. Fields named `chain_of_thought` or `reasoning` cannot be exported.
An `allow` rule also requires the classification to be permitted for the
destination. Pseudonyms use an HMAC key and an explicit caller-provided scope;
they are stable only for the same scope and key.

The structured payload has independent maximum depth and serialized-byte
limits, with cycle refusal. Text chunks are buffered up to the policy limit and
fully decoded before any sink call, so a split secret is not released in an
uninspected prefix. V1
supports only UTF-8 `text/plain` and `application/json` attachments, subject to
per-attachment and count limits. Binary content, invalid UTF-8, unsupported
types, interrupted streams, oversized input, invalid structured values and
policy errors refuse before delivery.

The returned audit record contains the policy/schema versions, declared
destination and purpose, transformation counts, detector version, and an
optional SHA-256 digest of a restricted evidence reference. It contains no raw
payload, text, attachment, or model reasoning.

## Integrating an offline run importer

An importer can pass its run summary as `payload`, generated narrative as
`text_chunks`, and eligible bounded textual artifacts as `attachments`. It
should classify every exported path in its policy and give the receiving
adapter a specific `SinkDescriptor`; it must not treat the importer itself as a
trusted destination. Importers should use a fresh, engagement-specific
`pseudonym_scope` when stable correlation is needed and provide only an opaque
restricted evidence reference for the audit digest.

The boundary does not inspect operational tool requests. Importers must keep
their execution arguments on their existing authorization path and pass only a
copy intended for export to this API.

`export_langsmith_inventory` requires the concrete `ExportBoundary`, derives a
selected inventory report and accepts only a registered `report` sink. It passes
the snapshot's engagement-bound restricted reference for the audit digest. Its
policy still controls which report fields may leave the boundary; raw LangSmith
trace content is absent from the normalized snapshot and has no export fallback.

## Corpus metric limits

`tests/fixtures/export_privacy_corpus_v1.json` contains only synthetic labels.
`evaluate_privacy_corpus` reports the policy/detector versions, record count,
labeled sensitive-field count, unchanged labeled sensitive fields, transformed
or omitted labeled benign fields, and unsupported cases. The detector covers the existing
credential redactor plus email and US Social Security-number patterns for
allowed text. Corpus results measure only those fixture labels; they do not
establish detection of arbitrary identifiers, secrets, encodings, or files.
