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
| `model_provider` | A policy may register an exact `(sink_id, destination, purpose)` tuple. | No provider/export adapter currently calls the boundary. | `fixture-provider` exercises nested tool inputs/results and text streams. |
| `telemetry` | A policy may register an exact tuple. | No telemetry exporter currently calls the boundary. | `fixture-telemetry` exercises field transformation. |
| `report` | A policy may register an exact tuple. | `cops.evidence.assessment.export_assessment_report` derives a local assessment with `report()` and calls `ExportBoundary.export` immediately before the caller-provided sink. It does not select a recipient or make a network request. | A synthetic envelope/receipt test exercises the adapter with a registered fake sink and refusal; `fixture-report` exercises bounded text attachments. |
| `diagnostic` | A policy may register an exact tuple. | No outbound diagnostic adapter currently calls the boundary. | `fixture-diagnostic` exercises safe audit output. |

`export_assessment_report` is the only integrated outward adapter in this
revision. Its sink is caller-provided, so its end-to-end test proves that the
adapter transforms the assessment before the fake sink receives it; it does not
prove delivery behavior or retention for a provider or durable recipient. The
fixture sink IDs are test-only declarations. They do not configure a provider,
telemetry service, report recipient, or diagnostic upload. A future adapter
must declare its real stable sink ID, destination and purpose in a reviewed
policy, then call this boundary immediately before the one send operation.

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

The later #246 LangSmith importer should call `ExportBoundary` with its own
policy and descriptor. It should use `export_assessment_report` only if it
deliberately maps imported content into validated COPS envelopes and receipts.

## Corpus metric limits

`tests/fixtures/export_privacy_corpus_v1.json` contains only synthetic labels.
`evaluate_privacy_corpus` reports the policy/detector versions, record count,
labeled sensitive-field count, unchanged labeled sensitive fields, transformed
or omitted labeled benign fields, and unsupported cases. The detector covers the existing
credential redactor plus email and US Social Security-number patterns for
allowed text. Corpus results measure only those fixture labels; they do not
establish detection of arbitrary identifiers, secrets, encodings, or files.
