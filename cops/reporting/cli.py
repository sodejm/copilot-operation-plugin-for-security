"""Private file output for the offline assessment report command."""

from __future__ import annotations

import json
import os
from pathlib import Path

from cops.evidence.canonical import EvidenceError, decode_json

from .assessment import ReportError, build_assessment_report, render_markdown

_MAX_INPUT_BYTES = 4 * 1024 * 1024


def command_engagement_report(args: object) -> int:
    """Validate one local bundle and write exclusive, owner-only report files."""
    source = Path(args.input)
    json_output = Path(args.json_output)
    markdown_output = Path(args.markdown_output)
    if json_output == markdown_output or json_output.resolve() == markdown_output.resolve():
        raise ReportError("report output paths must differ")
    try:
        with source.open("rb") as stream:
            raw = stream.read(_MAX_INPUT_BYTES + 1)
        bundle = decode_json(raw, max_bytes=_MAX_INPUT_BYTES)
    except (OSError, EvidenceError) as error:
        raise ReportError("cannot read valid bounded assessment input") from error
    report = build_assessment_report(bundle)
    outputs = (
        (json_output, (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")),
        (markdown_output, render_markdown(report).encode("utf-8")),
    )
    if any(path.exists() or path.is_symlink() for path, _ in outputs):
        raise ReportError("report output already exists")
    created: list[Path] = []
    try:
        for path, content in outputs:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
    except OSError as error:
        for path in created:
            path.unlink(missing_ok=True)
        raise ReportError("cannot write private assessment outputs") from error
    return 0
