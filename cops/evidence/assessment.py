"""Provider-independent receipt and observation assessment; reports omit payloads."""

import math
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .canonical import EvidenceError, timestamp
from .export_policy import Attachment, ExportBoundary, ExportRefused, ExportSink, SanitizedExport
from .validation import validate_envelope, validate_receipt


def assess(envelope, receipt, *, as_of, max_age_seconds, max_bytes=1024 * 1024, max_depth=32):
    validate_envelope(envelope, max_bytes=max_bytes, max_depth=max_depth)
    validate_receipt(receipt)
    if (
        receipt["acquisition_id"] != envelope["acquisition_id"]
        or receipt["tenant"] != envelope["source"]["tenant"]
        or receipt["scope"] != envelope["source"]["scope"]
        or receipt["request_fingerprint"] != envelope["request_fingerprint"]
    ):
        raise EvidenceError("acquisition_mismatch")
    if type(max_age_seconds) not in (int, float) or not math.isfinite(max_age_seconds) or max_age_seconds < 0:
        raise EvidenceError("invalid_limit")
    now = timestamp(as_of)
    observed = envelope["observed"]["at"]
    freshness = "unknown"
    if observed is not None:
        age = (now - timestamp(observed)).total_seconds()
        if age >= 0:
            freshness = "fresh" if age <= max_age_seconds else "stale"
    return {"completeness": receipt["status"], "freshness": freshness}


def report(envelopes, receipt, *, as_of, max_age_seconds, max_bytes=1024 * 1024, max_depth=32):
    validate_receipt(receipt)
    return {
        "acquisition_id": receipt["acquisition_id"],
        "status": receipt["status"],
        "records": [
            {
                "record_id": item["record_id"],
                **assess(
                    item,
                    receipt,
                    as_of=as_of,
                    max_age_seconds=max_age_seconds,
                    max_bytes=max_bytes,
                    max_depth=max_depth,
                ),
            }
            for item in envelopes
        ],
    }


def _require_destination(sink: ExportSink, expected_destination: str) -> None:
    """Keep each public adapter bound to its declared destination class."""
    if sink.descriptor.destination != expected_destination:
        raise ExportRefused("adapter_destination_mismatch")


def _export_assessment(
    envelopes: Sequence[Mapping[str, Any]],
    receipt: Mapping[str, Any],
    *,
    as_of: str,
    max_age_seconds: int | float,
    boundary: ExportBoundary,
    sink: ExportSink,
    pseudonym_scope: str,
    text_chunks: Iterable[bytes | str] | None = None,
    attachments: Sequence[Attachment] = (),
    restricted_evidence_reference: str | None = None,
    max_bytes: int = 1024 * 1024,
    max_depth: int = 32,
) -> SanitizedExport:
    """Build one policy-transformed assessment and deliver it to ``sink``."""
    assessment = report(
        envelopes,
        receipt,
        as_of=as_of,
        max_age_seconds=max_age_seconds,
        max_bytes=max_bytes,
        max_depth=max_depth,
    )
    return boundary.export(
        sink,
        {"assessment": assessment},
        text_chunks=text_chunks,
        attachments=attachments,
        restricted_evidence_reference=restricted_evidence_reference,
        pseudonym_scope=pseudonym_scope,
    )


def export_assessment_report(
    envelopes: Sequence[Mapping[str, Any]],
    receipt: Mapping[str, Any],
    *,
    as_of: str,
    max_age_seconds: int | float,
    boundary: ExportBoundary,
    sink: ExportSink,
    pseudonym_scope: str,
    text_chunks: Iterable[bytes | str] | None = None,
    attachments: Sequence[Attachment] = (),
    restricted_evidence_reference: str | None = None,
    max_bytes: int = 1024 * 1024,
    max_depth: int = 32,
) -> SanitizedExport:
    """Export a locally derived assessment to a declared report sink."""
    _require_destination(sink, "report")
    return _export_assessment(
        envelopes,
        receipt,
        as_of=as_of,
        max_age_seconds=max_age_seconds,
        boundary=boundary,
        sink=sink,
        pseudonym_scope=pseudonym_scope,
        text_chunks=text_chunks,
        attachments=attachments,
        restricted_evidence_reference=restricted_evidence_reference,
        max_bytes=max_bytes,
        max_depth=max_depth,
    )


def export_provider_assessment(
    envelopes: Sequence[Mapping[str, Any]],
    receipt: Mapping[str, Any],
    *,
    as_of: str,
    max_age_seconds: int | float,
    boundary: ExportBoundary,
    sink: ExportSink,
    pseudonym_scope: str,
    text_chunks: Iterable[bytes | str] | None = None,
    attachments: Sequence[Attachment] = (),
    restricted_evidence_reference: str | None = None,
    max_bytes: int = 1024 * 1024,
    max_depth: int = 32,
) -> SanitizedExport:
    """Export a locally derived assessment to a model-provider contract sink.

    The caller supplies the sink; this function creates no provider client or
    network request.
    """
    _require_destination(sink, "model_provider")
    return _export_assessment(
        envelopes,
        receipt,
        as_of=as_of,
        max_age_seconds=max_age_seconds,
        boundary=boundary,
        sink=sink,
        pseudonym_scope=pseudonym_scope,
        text_chunks=text_chunks,
        attachments=attachments,
        restricted_evidence_reference=restricted_evidence_reference,
        max_bytes=max_bytes,
        max_depth=max_depth,
    )


def export_assessment_telemetry(
    envelopes: Sequence[Mapping[str, Any]],
    receipt: Mapping[str, Any],
    *,
    as_of: str,
    max_age_seconds: int | float,
    boundary: ExportBoundary,
    sink: ExportSink,
    pseudonym_scope: str,
    text_chunks: Iterable[bytes | str] | None = None,
    attachments: Sequence[Attachment] = (),
    restricted_evidence_reference: str | None = None,
    max_bytes: int = 1024 * 1024,
    max_depth: int = 32,
) -> SanitizedExport:
    """Export a locally derived assessment to a telemetry contract sink.

    The caller supplies the sink; this function creates no telemetry client or
    network request.
    """
    _require_destination(sink, "telemetry")
    return _export_assessment(
        envelopes,
        receipt,
        as_of=as_of,
        max_age_seconds=max_age_seconds,
        boundary=boundary,
        sink=sink,
        pseudonym_scope=pseudonym_scope,
        text_chunks=text_chunks,
        attachments=attachments,
        restricted_evidence_reference=restricted_evidence_reference,
        max_bytes=max_bytes,
        max_depth=max_depth,
    )
