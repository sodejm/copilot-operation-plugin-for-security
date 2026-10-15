"""Command-line entry point for bounded offline artifact assessments."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import CAPABILITIES, ArtifactAssessmentError, assess


CLI_MAX_INPUT_BYTES = 6_291_456


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m cops.assessments")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("assess", help="assess supplied offline artifacts")
    add_assessment_arguments(command)
    return parser


def add_assessment_arguments(command: argparse.ArgumentParser) -> None:
    """Share the bounded assessment interface with the main operator CLI."""
    command.add_argument("capability", choices=sorted(CAPABILITIES))
    command.add_argument("--input", required=True, help="JSON file, or - for standard input")
    command.add_argument("--as-of", required=True, help="canonical RFC 3339 assessment timestamp")
    command.add_argument("--engagement-id", default="eng-offline-artifact")
    command.add_argument("--result-id", default="res-offline-artifact")
    command.add_argument("--scenario-id", default="COPS-OFFLINE-ARTIFACT")
    command.add_argument("--max-artifacts", type=int, default=64)
    command.add_argument("--max-artifact-bytes", type=int, default=1_048_576)
    command.add_argument("--max-total-bytes", type=int, default=4_194_304)


def _read_bounded(path: str) -> bytes:
    if path == "-":
        raw = sys.stdin.buffer.read(CLI_MAX_INPUT_BYTES + 1)
    else:
        with Path(path).open("rb") as stream:
            raw = stream.read(CLI_MAX_INPUT_BYTES + 1)
    if len(raw) > CLI_MAX_INPUT_BYTES:
        raise ArtifactAssessmentError("input_size_limit")
    return raw


def _decode_artifacts(value: Any) -> list[dict[str, object]]:
    if isinstance(value, dict):
        value = value.get("artifacts")
    if not isinstance(value, list):
        raise ArtifactAssessmentError("invalid_input_document")
    decoded: list[dict[str, object]] = []
    for artifact in value:
        if not isinstance(artifact, dict):
            raise ArtifactAssessmentError("invalid_artifact")
        item = dict(artifact)
        if "content_b64" in item:
            if "content" in item or not isinstance(item["content_b64"], str):
                raise ArtifactAssessmentError("invalid_content_b64")
            try:
                item["content"] = base64.b64decode(item.pop("content_b64"), validate=True)
            except (binascii.Error, ValueError):
                raise ArtifactAssessmentError("invalid_content_b64") from None
        decoded.append(item)
    return decoded


def _load_artifacts(path: str) -> list[dict[str, object]]:
    try:
        value = json.loads(_read_bounded(path))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ArtifactAssessmentError("invalid_input_json") from None
    return _decode_artifacts(value)


def command_assess(args: argparse.Namespace) -> int:
    try:
        report = assess(
            args.capability,
            _load_artifacts(args.input),
            as_of=args.as_of,
            engagement_id=args.engagement_id,
            result_id=args.result_id,
            scenario_id=args.scenario_id,
            max_artifacts=args.max_artifacts,
            max_artifact_bytes=args.max_artifact_bytes,
            max_total_bytes=args.max_total_bytes,
        )
    except ArtifactAssessmentError as exc:
        print(json.dumps({"error": exc.code}, sort_keys=True), file=sys.stderr)
        return 2
    except OSError:
        print(json.dumps({"error": "input_read_error"}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return command_assess(_parser().parse_args(argv))


if __name__ == "__main__":  # pragma: no cover - exercised through the module entry point
    raise SystemExit(main())
