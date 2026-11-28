"""Machine-only CLI; requests are stdin data, never filesystem destinations."""

import argparse
import os
import sys

from .catalog import declarations, validate_catalog
from .contracts import MAX_BYTES, OperationError, decode, encode, response
from .service import OperationService


def add_parser(subparsers):
    parser = subparsers.add_parser("tools", help="discover and invoke bounded headless operations")
    commands = parser.add_subparsers(dest="tools_command", required=True)
    commands.add_parser("list").add_argument("--json", action="store_true")
    describe = commands.add_parser("describe")
    describe.add_argument("operation_id")
    describe.add_argument("--json", action="store_true")
    commands.add_parser("validate")
    invoke = commands.add_parser("invoke")
    invoke.add_argument("--request", choices=["-"], default="-", help="one JSON request on stdin")


def command(args):
    try:
        catalog = declarations()
        if args.tools_command == "list":
            result = {"schema_version": "cops.operation-catalog/v1", "operations": catalog}
        elif args.tools_command == "describe":
            result = next((item for item in catalog if item["operation_id"] == args.operation_id), None)
            if result is None:
                raise OperationError("unknown_operation")
        elif args.tools_command == "validate":
            validate_catalog(catalog)
            result = {"status": "valid", "operations": len(catalog)}
        else:
            result = OperationService(runtime_config=os.environ.get("COPS_RUNTIME_CONFIG")).invoke(
                decode(sys.stdin.buffer.read(MAX_BYTES + 1))
            )
    except OperationError as exc:
        result = response(status="failed", code=exc.code)
    sys.stdout.buffer.write(encode(result) + b"\n")
    return 0 if result.get("status") not in {"failed", "blocked", "needs_input"} else 2


def main():
    parser = argparse.ArgumentParser(prog="python -m cops.operations")
    add_parser(parser.add_subparsers(dest="command", required=True))
    return command(parser.parse_args())
