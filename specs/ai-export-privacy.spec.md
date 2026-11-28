# AI export privacy policy

## Scope

COPS provides a local, fail-closed transformation boundary for evidence copied to
an AI provider, telemetry, report, or diagnostic sink. In this revision,
`export_assessment_report` is the supported caller-provided assessment-report
adapter; provider, telemetry, and diagnostic adapters are unavailable. This
contract applies to copies of evidence only. It does not inspect or mutate the
separately authorized operational request sent to a tool or target.

The v1 policy is versioned as `cops.export-policy/v1`. A policy declares an
allowlist of field paths, a classification and deterministic action for each
field, and the destination/purpose combinations that may receive the result.
Unknown fields are omitted under the field allowlist. Unknown destinations, policy parse failures, unsupported
attachments, invalid encodings, oversize input, incomplete streams, and sink
mismatches are refused before delivery.

## Transform contract

Supported structured values are JSON-compatible mappings, sequences, strings,
numbers, booleans and null. Each leaf must have an exact allowlisted path.
Actions are `allow`, `redact`, `omit`, and `pseudonymize`. Allowed text is still
scanned for credentials and the v1 synthetic personal-data detectors. A
pseudonym is deterministic only within an explicit caller-supplied scope.
`chain_of_thought` and `reasoning` fields are never exportable.

The boundary accepts a bounded iterable of text chunks and buffers it until the
whole input is inspected. It emits no partial output. Structured payloads have
independent byte and depth limits and refuse cycles. The attachment surface is
limited to UTF-8 `text/plain` and `application/json`; each attachment is
bounded before decoding and transformation.

## Sink contract

A caller supplies a `SinkDescriptor` and sink callback. The descriptor’s stable
identifier, destination, and purpose must exactly match the selected policy
destination. The callback receives only `SanitizedExport`. Callback and source
failures have sanitized errors without chained source exception text and never
retry with the source payload. The caller may retry by calling the boundary
again; that attempt is independently transformed. Cancellation propagates
without delivery.

The boundary exposes a sanitized audit record containing policy version,
destination/purpose, transformation counts, and a digest of an optional
restricted evidence reference. It never includes source fields or model
reasoning.

## Non-goals

This is not universal DLP, a claim that all COPS paths currently call the
boundary, an anonymization guarantee, raw evidence retention, or a guarantee
about a provider after delivery. Unsupported binary formats and attachments over
the configured limit are refused rather than quarantined by default.
