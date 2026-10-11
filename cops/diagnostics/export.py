"""Controlled export adapter for locally generated diagnostic reports."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from cops.evidence.export_policy import (
    Attachment,
    ExportBoundary,
    ExportRefused,
    ExportSink,
    SanitizedExport,
)

from .models import DiagnosticReport


def export_diagnostic_report(
    diagnostic: DiagnosticReport,
    *,
    boundary: ExportBoundary,
    sink: ExportSink,
    pseudonym_scope: str,
    text_chunks: Iterable[bytes | str] | None = None,
    attachments: Sequence[Attachment] = (),
    restricted_evidence_reference: str | None = None,
) -> SanitizedExport:
    """Transform a diagnostic report immediately before a caller-provided sink.

    ``command_diagnostics`` renders local terminal output only. Callers that
    choose to persist or transmit a report use this adapter, which places the
    policy boundary directly before ``sink.send`` without selecting a recipient
    or changing operational requests.
    """
    if sink.descriptor.destination != "diagnostic":
        raise ExportRefused("adapter_destination_mismatch")

    return boundary.export(
        sink,
        {"diagnostic": diagnostic.to_dict()},
        text_chunks=text_chunks,
        attachments=attachments,
        restricted_evidence_reference=restricted_evidence_reference,
        pseudonym_scope=pseudonym_scope,
    )
