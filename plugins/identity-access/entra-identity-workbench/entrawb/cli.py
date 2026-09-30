"""Operator command-line interface for the Entra Identity Workbench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import analyze_identity_graph
from .graph import build_identity_graph
from .ingestion import ingest_tenant_export
from .models import EntraError
from .reporting import render_json_report, render_markdown_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="entrawb",
        description="Offline Entra ID and AI Agent identity graph modeling and exposure analysis.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="analyze a tenant export manifest")
    analyze_parser.add_argument("--manifest", type=Path, required=True, help="path to manifest.json")
    analyze_parser.add_argument("--output", type=Path, help="write report output to file")
    analyze_parser.add_argument("--json", action="store_true", help="output structured JSON instead of Markdown")

    graph_parser = subparsers.add_parser("graph", help="build and export the normalized identity graph")
    graph_parser.add_argument("--manifest", type=Path, required=True, help="path to manifest.json")
    graph_parser.add_argument("--output", type=Path, help="write graph JSON to file")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        manifest, sources = ingest_tenant_export(args.manifest)
        graph = build_identity_graph(manifest, sources)

        if args.command == "graph":
            data = graph.to_dict()
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                print(f"Wrote identity graph to {args.output}")
            else:
                print(json.dumps(data, indent=2))
            return 0

        elif args.command == "analyze":
            hypotheses = analyze_identity_graph(graph)
            if args.json:
                data = render_json_report(graph, hypotheses)
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                    print(f"Wrote analysis report to {args.output}")
                else:
                    print(json.dumps(data, indent=2))
            else:
                md = render_markdown_report(graph, hypotheses)
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(md + "\n", encoding="utf-8")
                    print(f"Wrote analysis report to {args.output}")
                else:
                    print(md)
            return 0

    except EntraError as exc:
        print(f"entrawb error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
