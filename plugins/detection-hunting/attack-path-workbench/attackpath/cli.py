"""Small local CLI. It never imports a network client."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import GateError, analyze, canonical, query_intent
from .report import markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline attack path workbench")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("analyze", help="Analyze a local manifest and export")
    run.add_argument("input", type=Path)
    run.add_argument("--output-dir", required=True, type=Path)
    intent = commands.add_parser("query-intent", help="Produce an unrendered Wiz query intent")
    intent.add_argument("--start", required=True)
    intent.add_argument("--target", required=True)
    intent.add_argument("--scope", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "query-intent":
            sys.stdout.buffer.write(canonical(query_intent(args.start, args.target, args.scope)))
            return 0
        if args.output_dir.exists():
            raise GateError(f"output directory exists: {args.output_dir}")
        report = analyze(args.input.resolve())
        args.output_dir.mkdir(parents=True)
        (args.output_dir / "report.json").write_bytes(canonical(report))
        (args.output_dir / "graph.json").write_bytes(canonical(report["graph"]))
        (args.output_dir / "report.md").write_text(markdown(report), encoding="utf-8")
        ledger = {"schema_version": "attackpath.ledger/v1", "run_id": report["run"]["run_id"],
                  "actions": report["actions"]}
        (args.output_dir / "remediation-ledger.json").write_bytes(canonical(ledger))
        print(json.dumps({"run_id": report["run"]["run_id"], "output_dir": str(args.output_dir)}, sort_keys=True))
        return 0
    except (GateError, OSError) as exc:
        print(f"attack-path-workbench: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
