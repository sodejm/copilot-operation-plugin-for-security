"""Small local CLI. It never imports a network client."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import GateError, analyze, canonical, query_intent
from .report import markdown


def add_ingestion_flags(command):
    for name in ("file-bytes", "total-bytes", "files", "line-bytes", "records", "json-depth"):
        command.add_argument("--max-" + name, type=int)


def ingestion_overrides(args):
    return {name: value for name in ("file_bytes", "total_bytes", "files", "line_bytes",
                                     "records", "json_depth") if (value := getattr(args, "max_" + name)) is not None}


def add_search_flags(command):
    for name in ("expansions", "frontier", "complete-paths", "partial-paths", "emitted-paths", "report-bytes"):
        command.add_argument("--max-" + name, type=int)


def search_overrides(args):
    return {name: value for name in ("expansions", "frontier", "complete_paths", "partial_paths",
                                     "emitted_paths", "report_bytes") if (value := getattr(args, "max_" + name)) is not None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline attack path workbench")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("analyze", help="Analyze a local manifest and export")
    run.add_argument("input", type=Path)
    run.add_argument("--output-dir", required=True, type=Path)
    add_ingestion_flags(run)
    add_search_flags(run)
    intent = commands.add_parser("query-intent", help="Produce an unrendered Wiz query intent")
    intent.add_argument("--start", required=True)
    intent.add_argument("--target", required=True)
    intent.add_argument("--scope", required=True)
    azure = commands.add_parser("analyze-azure", help="Analyze local Azure SDK evidence")
    azure.add_argument("--input", required=True, type=Path)
    azure.add_argument("--as-of", required=True)
    azure.add_argument("--output", required=True, type=Path)
    add_ingestion_flags(azure)
    collection = commands.add_parser("plan-azure-collection", help="Produce a read-only Azure collection plan")
    collection.add_argument("--scope-file", required=True, type=Path)
    collection.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command in ("analyze-azure", "plan-azure-collection"):
        from .azure.model import AzureError
        from .azure.report import analyze as analyze_azure
        from .azure.report import write_files
        try:
            if args.command == "analyze-azure":
                result = analyze_azure(args.input, args.as_of, args.output, ingestion_overrides(args))
            else:
                from .azure.collection import plan
                result = plan(args.scope_file)
                write_files(args.output, {"collection-plan.json": result}, 4194304)
                result = {"requests": len(result["requests"])}
            print(json.dumps(result, sort_keys=True))
            return 0
        except (AzureError, OSError, ValueError, RecursionError):
            # Source values, local paths and SDK diagnostics are not safe to echo.
            print("attack-path-workbench: Azure input or output validation failed", file=sys.stderr)
            return 2
    try:
        if args.command == "query-intent":
            sys.stdout.buffer.write(canonical(query_intent(args.start, args.target, args.scope)))
            return 0
        if args.output_dir.exists():
            raise GateError(f"output directory exists: {args.output_dir}")
        report = analyze(args.input, ingestion_overrides(args), search_overrides(args))
        ledger = {"schema_version": "attackpath.ledger/v1", "run_id": report["run"]["run_id"],
                  "actions": report["actions"]}
        contents = {
            "report.json": report,
            "graph.json": report["graph"],
            "report.md": markdown(report).encode("utf-8"),
            "remediation-ledger.json": ledger,
        }
        from .azure.model import AzureError
        from .azure.report import write_files
        limit = search_overrides(args).get("report_bytes", 33554432)
        try:
            write_files(args.output_dir, contents, limit)
        except AzureError as err:
            raise GateError(f"output validation failed: {err}") from err
        print(json.dumps({"run_id": report["run"]["run_id"], "output_dir": str(args.output_dir)}, sort_keys=True))
        return 0
    except (GateError, OSError, RecursionError):
        print("attack-path-workbench: input or output validation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
