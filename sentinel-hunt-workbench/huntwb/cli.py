"""Command-line interface for the offline Sentinel Hunt Workbench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .adapters import build_adapters, verify_adapters
from .contracts import validate_target
from .errors import ContentError, HuntWorkbenchError
from .evaluator import run_target
from .parameters import load_parameter_file
from .paths import load_json
from .rendering import compatibility_report, explain_hunt, list_hunts, render_hunt
from .reports import release_report


def _emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _load_external_evidence(path: str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        value = load_json(Path(path))
    except (OSError, UnicodeError, ValueError) as error:
        raise ContentError(f"cannot read external evidence JSON: {error}") from error
    if not isinstance(value, dict):
        raise ContentError("external evidence JSON must be an object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="huntwb", description="Offline Sentinel threat-hunt authoring workbench")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    explain = sub.add_parser("explain")
    explain.add_argument("hunt_id")
    render = sub.add_parser("render")
    render.add_argument("hunt_id")
    render.add_argument("--surface", required=True)
    render.add_argument("--params", "--parameters", dest="parameters")
    validate = sub.add_parser("validate")
    validate.add_argument("target")
    test = sub.add_parser("test")
    test.add_argument("target")
    test.add_argument("--seed", type=int, default=20260916)
    compatibility = sub.add_parser("compatibility")
    compatibility.add_argument("hunt_id")
    sub.add_parser("build-adapters")
    sub.add_parser("verify-adapters")
    report = sub.add_parser("release-report")
    report.add_argument("--seed", type=int, default=20260916)
    report.add_argument("--evidence")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "list":
            _emit(list_hunts())
        elif args.command == "explain":
            _emit(explain_hunt(args.hunt_id))
        elif args.command == "render":
            _emit(render_hunt(args.hunt_id, args.surface, load_parameter_file(args.parameters)))
        elif args.command == "validate":
            _emit(validate_target(args.target))
        elif args.command == "test":
            _emit(run_target(args.target, args.seed))
        elif args.command == "compatibility":
            _emit(compatibility_report(args.hunt_id))
        elif args.command == "build-adapters":
            _emit(build_adapters())
        elif args.command == "verify-adapters":
            _emit(verify_adapters())
        elif args.command == "release-report":
            _emit(release_report(args.seed, _load_external_evidence(args.evidence)))
        return 0
    except HuntWorkbenchError as error:
        print(json.dumps({"status": "failed", "error": str(error), "error_type": type(error).__name__}), file=sys.stderr)
        return error.exit_code
    except Exception as error:  # pragma: no cover - defensive CLI boundary
        print(json.dumps({"status": "failed", "error": str(error), "error_type": "InternalError"}), file=sys.stderr)
        return 6


if __name__ == "__main__":
    raise SystemExit(main())
