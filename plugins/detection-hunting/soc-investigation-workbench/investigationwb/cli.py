"""Small local CLI. Reports and errors never print input prose."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from .engine import ContractError, digest, import_result, next_steps, report, revise, validate
from .files import read_regular
from .vendor import handoff, sync, verify


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("JSON object contains duplicate keys.")
        value[key] = item
    return value


def read_json(path: Path) -> Any:
    return json.loads(read_regular(path).decode("utf-8"), object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ContractError("Non-finite JSON number.")))


def write_snapshot(path: Path, case: dict[str, Any]) -> None:
    """Validate before exclusive creation; use owner-only mode on POSIX."""
    validate(case)
    encoded = (json.dumps(case, indent=2, allow_nan=False) + "\n").encode()
    if len(encoded) > 8 * 1024 * 1024:
        raise ContractError("Output exceeds the 8 MiB case limit.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan analyst-led investigations; execute no queries.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "next", "report", "import", "revise", "handoff"):
        command = commands.add_parser(name)
        command.add_argument("case", type=Path)
        if name in ("import", "revise"):
            command.add_argument("input", type=Path)
            command.add_argument("--out", type=Path, required=True)
        if name == "handoff":
            command.add_argument("--step", required=True)
    command = commands.add_parser("verify-vendor")
    command.add_argument("--source", type=Path)
    command = commands.add_parser("vendor-sync")
    command.add_argument("source", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-vendor":
            output = verify(source=args.source)
        elif args.command == "vendor-sync":
            output = sync(args.source)
        else:
            case = validate(read_json(args.case))
            if args.command == "validate":
                output = {"status": "valid", "snapshot_hash": digest(case)}
            elif args.command == "next":
                output = next_steps(case)
            elif args.command == "report":
                output = report(case)
            elif args.command == "handoff":
                output = handoff(case, args.step)
            else:
                incoming = read_json(args.input)
                revised = import_result(case, incoming) if args.command == "import" else revise(case, incoming)
                write_snapshot(args.out, revised)
                output = {"status": "written", "snapshot_hash": digest(revised)}
        print(json.dumps(output, indent=2, allow_nan=False))
        return 0
    except ContractError as exc:
        print(json.dumps({"error": "contract", "message": str(exc)}), file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({"error": "input_or_io", "message": "Input is malformed, unavailable, or output already exists."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
