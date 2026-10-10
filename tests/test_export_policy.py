"""Tests for the v1 fail-closed AI/export evidence boundary."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from cops.evidence import build_envelope, export_assessment_report
from cops.evidence.export_policy import (
    POLICY_SCHEMA_VERSION,
    Attachment,
    Classification,
    DestinationRule,
    ExportAction,
    ExportBoundary,
    ExportPolicy,
    ExportRefused,
    FieldRule,
    SanitizedExport,
    SinkDescriptor,
    evaluate_privacy_corpus,
)
from cops.execution.redaction import StreamRedactor


class RecordingSink:
    def __init__(self, descriptor: SinkDescriptor, *, fail: bool = False) -> None:
        self.descriptor = descriptor
        self.fail = fail
        self.exports: list[SanitizedExport] = []

    def send(self, export: SanitizedExport) -> None:
        self.exports.append(export)
        if self.fail:
            raise RuntimeError("sink reported raw-sensitive-detail")


class FlakySink(RecordingSink):
    def __init__(self, descriptor: SinkDescriptor, *, failures: int) -> None:
        super().__init__(descriptor)
        self.failures = failures

    def send(self, export: SanitizedExport) -> None:
        self.exports.append(export)
        if self.failures:
            self.failures -= 1
            raise RuntimeError("sink reported raw-sensitive-detail")


class ExplodingMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise KeyError(key)

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return 0

    def items(self):
        raise RuntimeError("source includes raw-sensitive-detail")


def policy() -> ExportPolicy:
    destinations = tuple(
        DestinationRule(
            sink_id=sink_id,
            destination=destination,
            purpose=purpose,
            permitted_classifications=frozenset({Classification.PUBLIC, Classification.INTERNAL}),
        )
        for sink_id, destination, purpose in (
            ("fixture-provider", "model_provider", "assessment"),
            ("fixture-telemetry", "telemetry", "security-observability"),
            ("fixture-report", "report", "operator-report"),
            ("fixture-diagnostic", "diagnostic", "support-diagnostic"),
        )
    )
    return ExportPolicy(
        policy_id="synthetic-test-policy",
        version="2026-10-10.1",
        field_rules=(
            FieldRule("summary", Classification.PUBLIC, ExportAction.ALLOW),
            FieldRule("tool.arguments.api_key", Classification.SECRET, ExportAction.REDACT),
            FieldRule("tool.arguments.customer_id", Classification.PERSONAL, ExportAction.PSEUDONYMIZE),
            FieldRule("tool.result.customer_email", Classification.PERSONAL, ExportAction.REDACT),
            FieldRule("tool.result.status", Classification.PUBLIC, ExportAction.ALLOW),
            FieldRule("text", Classification.INTERNAL, ExportAction.ALLOW),
            FieldRule("attachment.content", Classification.INTERNAL, ExportAction.ALLOW),
        ),
        destinations=destinations,
        max_stream_bytes=80,
        max_attachment_bytes=80,
        max_attachments=2,
        max_payload_bytes=4096,
        max_payload_depth=8,
    )


def boundary() -> ExportBoundary:
    return ExportBoundary(
        policy(),
        pseudonym_key=b"only-synthetic-test-key",
        redactor=StreamRedactor(known_secrets=["unique-secret-split-across-chunks"]),
    )


def assessment_policy() -> ExportPolicy:
    return ExportPolicy(
        policy_id="synthetic-assessment-policy",
        version="2026-10-10.1",
        field_rules=(
            FieldRule("assessment.acquisition_id", Classification.INTERNAL, ExportAction.PSEUDONYMIZE),
            FieldRule("assessment.status", Classification.PUBLIC, ExportAction.ALLOW),
            FieldRule("assessment.records.*.record_id", Classification.INTERNAL, ExportAction.PSEUDONYMIZE),
            FieldRule("assessment.records.*.completeness", Classification.PUBLIC, ExportAction.ALLOW),
            FieldRule("assessment.records.*.freshness", Classification.PUBLIC, ExportAction.ALLOW),
        ),
        destinations=(
            DestinationRule(
                sink_id="assessment-report-fixture",
                destination="report",
                purpose="assessment-report-export",
                permitted_classifications=frozenset({Classification.PUBLIC, Classification.INTERNAL}),
            ),
        ),
        max_payload_bytes=4096,
        max_payload_depth=8,
    )


def assessment_boundary() -> ExportBoundary:
    return ExportBoundary(assessment_policy(), pseudonym_key=b"only-synthetic-test-key")


def synthetic_envelope() -> dict[str, object]:
    return build_envelope(
        acquisition_id="collection-1",
        product="graph",
        api="v1.0/users",
        tenant="tenant-1",
        scope=["users"],
        identity="user-1",
        locator="user-1",
        payload={"id": "user-1"},
        acquired_at="2026-09-28T00:00:00Z",
        transformed_at="2026-09-28T00:00:00Z",
        request_fingerprint="a" * 64,
        page=1,
    )


def synthetic_receipt() -> dict[str, object]:
    return {
        "schema_version": "cops.acquisition/v1",
        "acquisition_id": "collection-1",
        "generation": 1,
        "adapter": "test",
        "adapter_version": "1",
        "tenant": "tenant-1",
        "scope": ["users"],
        "request_fingerprint": "a" * 64,
        "started_at": "2026-09-28T00:00:00Z",
        "finished_at": "2026-09-28T00:00:00Z",
        "status": "partial",
        "reasons": ["record_limit"],
        "consistency": "unknown",
        "limits": {
            "pages": 10,
            "attempts": 10,
            "records": 10,
            "response_bytes": 1024,
            "total_bytes": 10240,
            "record_bytes": 1024,
            "storage_bytes": 10240,
            "depth": 32,
            "request_seconds": 10,
            "active_seconds": 100,
            "retries": 1,
        },
        "consumed": {
            "pages": 1,
            "attempts": 1,
            "records": 1,
            "duplicates": 0,
            "bytes": 100,
            "storage_bytes": 100,
            "active_seconds": 1,
        },
    }


def test_policy_mapping_is_versioned_and_rejects_reasoning_exports() -> None:
    source = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_id": "synthetic",
        "version": "1",
        "field_rules": [{"path": "summary", "classification": "public", "action": "allow"}],
        "destinations": [
            {
                "sink_id": "fixture-provider",
                "destination": "model_provider",
                "purpose": "assessment",
                "permitted_classifications": ["public"],
            }
        ],
    }
    assert ExportPolicy.from_mapping(source).schema_version == POLICY_SCHEMA_VERSION
    source["field_rules"] = [{"path": "chain_of_thought", "classification": "internal", "action": "allow"}]
    with pytest.raises(ValueError, match="invalid export policy"):
        ExportPolicy.from_mapping(source)


@pytest.mark.parametrize("invalid_limit", [True, 1.5, "1024"])
def test_policy_mapping_rejects_non_integer_limits(invalid_limit: object) -> None:
    source = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_id": "synthetic",
        "version": "1",
        "field_rules": [{"path": "summary", "classification": "public", "action": "allow"}],
        "destinations": [
            {
                "sink_id": "fixture-provider",
                "destination": "model_provider",
                "purpose": "assessment",
                "permitted_classifications": ["public"],
            }
        ],
        "limits": {"max_payload_bytes": invalid_limit},
    }
    with pytest.raises(ValueError, match="invalid export policy"):
        ExportPolicy.from_mapping(source)


def test_nested_tool_fields_are_transformed_before_each_supported_sink() -> None:
    source = {
        "summary": "Safe synthetic summary",
        "tool": {
            "arguments": {"api_key": "synthetic-api-key", "customer_id": "customer-1842"},
            "result": {"customer_email": "person@example.test", "status": "ok"},
        },
        "unallowlisted": "must-not-leave",
        "chain_of_thought": "must-not-leave",
    }
    for rule in policy().destinations:
        sink = RecordingSink(SinkDescriptor(rule.sink_id, rule.destination, rule.purpose))
        export = boundary().export(sink, source, pseudonym_scope="engagement-a")
        serialized = json.dumps(export.payload, sort_keys=True)
        assert len(sink.exports) == 1
        assert "synthetic-api-key" not in serialized
        assert "customer-1842" not in serialized
        assert "person@example.test" not in serialized
        assert "must-not-leave" not in serialized
        assert export.payload["tool"]["arguments"]["api_key"] == "[REDACTED:SECRET]"
        assert export.payload["tool"]["arguments"]["customer_id"].startswith("pseudonym-v1:")
        assert export.payload["tool"]["result"]["customer_email"] == "[REDACTED:PERSONAL]"
        assert export.payload["tool"]["result"]["status"] == "ok"
        assert export.audit.transformations["redacted"] == 2


def test_pseudonyms_are_stable_only_within_explicit_scope() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-provider", "model_provider", "assessment"))
    source = {"tool": {"arguments": {"customer_id": "customer-1842"}}}
    first = boundary().export(sink, source, pseudonym_scope="engagement-a")
    second = boundary().export(sink, source, pseudonym_scope="engagement-a")
    third = boundary().export(sink, source, pseudonym_scope="engagement-b")
    first_id = first.payload["tool"]["arguments"]["customer_id"]
    assert first_id == second.payload["tool"]["arguments"]["customer_id"]
    assert first_id != third.payload["tool"]["arguments"]["customer_id"]
    with pytest.raises(ExportRefused, match="pseudonym_scope_required"):
        boundary().export(sink, source, pseudonym_scope="")


def test_stream_is_buffered_and_redacted_across_chunk_boundary_before_sink_call() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-provider", "model_provider", "assessment"))
    raw = "Bearer unique-secret-split-across-chunks and person@example.test"
    export = boundary().export(
        sink,
        {"summary": "stream test"},
        text_chunks=[raw[:21], raw[21:37], raw[37:]],
        pseudonym_scope="scope",
    )
    assert len(sink.exports) == 1
    assert "unique-secret-split-across-chunks" not in export.text
    assert "person@example.test" not in export.text
    assert "[REDACTED" in export.text


def test_incomplete_or_oversize_stream_never_calls_sink() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-provider", "model_provider", "assessment"))

    def interrupted():
        yield "safe first chunk"
        raise RuntimeError("source includes raw detail")

    with pytest.raises(ExportRefused, match="stream_incomplete"):
        boundary().export(sink, {"summary": "x"}, text_chunks=interrupted(), pseudonym_scope="scope")
    with pytest.raises(ExportRefused, match="stream_size_exceeded"):
        boundary().export(sink, {"summary": "x"}, text_chunks=["x" * 81], pseudonym_scope="scope")
    assert sink.exports == []


def test_attachment_is_bounded_decoded_and_sanitized_before_delivery() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-report", "report", "operator-report"))
    export = boundary().export(
        sink,
        {"summary": "attachment test"},
        attachments=[Attachment("text/plain", [b"person@example.test unique-secret-split-across-chunks"])],
        pseudonym_scope="scope",
    )
    assert b"person@example.test" not in export.attachments[0].content
    assert b"unique-secret-split-across-chunks" not in export.attachments[0].content
    assert export.attachments[0].ordinal == 1


@pytest.mark.parametrize(
    "attachment",
    [
        Attachment("application/pdf", [b"synthetic"]),
        Attachment("text/plain", [b"\xff"]),
        Attachment("text/plain", [b"x" * 81]),
    ],
)
def test_unsupported_or_invalid_attachment_refuses_without_sink_call(attachment: Attachment) -> None:
    sink = RecordingSink(SinkDescriptor("fixture-report", "report", "operator-report"))
    with pytest.raises(ExportRefused):
        boundary().export(sink, {"summary": "x"}, attachments=[attachment], pseudonym_scope="scope")
    assert sink.exports == []


def test_unknown_destination_or_sink_failure_has_no_raw_fallback() -> None:
    source = {"tool": {"arguments": {"api_key": "synthetic-api-key"}}}
    unknown = RecordingSink(SinkDescriptor("unregistered", "model_provider", "assessment"))
    with pytest.raises(ExportRefused, match="unregistered_destination"):
        boundary().export(unknown, source, pseudonym_scope="scope")
    assert unknown.exports == []

    failing = RecordingSink(SinkDescriptor("fixture-provider", "model_provider", "assessment"), fail=True)
    with pytest.raises(ExportRefused, match="sanitized_sink_delivery_failed") as caught:
        boundary().export(failing, source, pseudonym_scope="scope")
    assert "synthetic-api-key" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert len(failing.exports) == 1
    assert "synthetic-api-key" not in json.dumps(failing.exports[0].payload)


def test_oversize_deep_or_cyclic_structured_payload_never_calls_sink() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-provider", "model_provider", "assessment"))
    with pytest.raises(ExportRefused, match="structured_payload_size_exceeded"):
        boundary().export(sink, {"summary": "x" * 4097}, pseudonym_scope="scope")

    deep: dict[str, object] = {"summary": "safe"}
    cursor = deep
    for _ in range(9):
        next_level: dict[str, object] = {}
        cursor["nested"] = next_level
        cursor = next_level
    with pytest.raises(ExportRefused, match="structured_payload_depth_exceeded"):
        boundary().export(sink, deep, pseudonym_scope="scope")

    cyclic: dict[str, object] = {"summary": "safe"}
    cyclic["nested"] = cyclic
    with pytest.raises(ExportRefused, match="structured_payload_cycle"):
        boundary().export(sink, cyclic, pseudonym_scope="scope")
    assert sink.exports == []


def test_audit_contains_only_versions_counts_and_restricted_reference_digest() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-diagnostic", "diagnostic", "support-diagnostic"))
    export = boundary().export(
        sink,
        {"summary": "diagnostic"},
        restricted_evidence_reference="opaque-restricted-reference-42",
        pseudonym_scope="scope",
    )
    audit = json.dumps(export.audit.__dict__, sort_keys=True)
    assert "opaque-restricted-reference-42" not in audit
    assert "synthetic-api-key" not in audit
    assert export.audit.restricted_evidence_reference_sha256 is not None


def test_synthetic_corpus_emits_documented_privacy_metrics() -> None:
    fixture = Path(__file__).parent / "fixtures" / "export_privacy_corpus_v1.json"
    corpus: list[Mapping[str, object]] = json.loads(fixture.read_text())
    metrics = evaluate_privacy_corpus(policy(), corpus, pseudonym_key=b"only-synthetic-test-key")
    assert metrics.policy_version == "2026-10-10.1"
    assert metrics.records == 2
    assert metrics.sensitive_fields == 3
    assert metrics.missed_sensitive_fields == 0
    assert metrics.unnecessary_redactions == 0
    assert metrics.unsupported_cases == 0


def test_caller_may_retry_after_sanitized_sink_refusal() -> None:
    sink = FlakySink(
        SinkDescriptor("fixture-provider", "model_provider", "assessment"),
        failures=1,
    )
    source = {"tool": {"arguments": {"api_key": "synthetic-api-key"}}}

    with pytest.raises(ExportRefused, match="sanitized_sink_delivery_failed") as caught:
        boundary().export(sink, source, pseudonym_scope="scope")
    assert caught.value.__cause__ is None

    recovered = boundary().export(sink, source, pseudonym_scope="scope")
    assert recovered is sink.exports[-1]
    assert len(sink.exports) == 2
    assert all("synthetic-api-key" not in json.dumps(item.payload) for item in sink.exports)


def test_cancellation_propagates_without_sink_delivery() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-provider", "model_provider", "assessment"))

    def cancelled():
        yield "safe"
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        boundary().export(sink, {"summary": "safe"}, text_chunks=cancelled(), pseudonym_scope="scope")
    assert sink.exports == []


def test_source_failures_are_sanitized_without_chained_cause() -> None:
    sink = RecordingSink(SinkDescriptor("fixture-provider", "model_provider", "assessment"))
    with pytest.raises(ExportRefused, match="policy_transformation_refused") as caught:
        boundary().export(sink, ExplodingMapping(), pseudonym_scope="scope")
    assert caught.value.__cause__ is None
    assert "raw-sensitive-detail" not in str(caught.value)
    assert sink.exports == []


def test_assessment_export_adapter_transforms_before_caller_sink_and_refuses_unregistered_sink() -> None:
    envelope = synthetic_envelope()
    receipt = synthetic_receipt()
    sink = RecordingSink(SinkDescriptor("assessment-report-fixture", "report", "assessment-report-export"))
    exported = export_assessment_report(
        [envelope],
        receipt,
        as_of="2026-09-28T00:00:30Z",
        max_age_seconds=60,
        boundary=assessment_boundary(),
        sink=sink,
        pseudonym_scope="engagement-a",
    )
    serialized = json.dumps(exported.payload, sort_keys=True)
    assert sink.exports == [exported]
    assert receipt["acquisition_id"] not in serialized
    assert envelope["record_id"] not in serialized
    assessment = exported.payload["assessment"]
    assert assessment["status"] == "partial"
    assert assessment["records"][0]["completeness"] == "partial"

    refused = RecordingSink(SinkDescriptor("unregistered", "report", "assessment-report-export"))
    with pytest.raises(ExportRefused, match="unregistered_destination"):
        export_assessment_report(
            [envelope],
            receipt,
            as_of="2026-09-28T00:00:30Z",
            max_age_seconds=60,
            boundary=assessment_boundary(),
            sink=refused,
            pseudonym_scope="engagement-a",
        )
    assert refused.exports == []
