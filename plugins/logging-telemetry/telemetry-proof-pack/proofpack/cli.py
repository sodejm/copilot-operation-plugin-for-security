"""Operator command-line interface for Telemetry Proof Pack."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from proofpack.correlator import correlate_pipeline_evidence
    from proofpack.models import ProofError, RunManifest
    from proofpack.reporting import render_json_report, render_markdown_report
else:
    from .correlator import correlate_pipeline_evidence
    from .models import ProofError, RunManifest
    from .reporting import render_json_report, render_markdown_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofpack",
        description="Telemetry-to-detection proof pack and multi-stage pipeline correlation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # trace command
    trace_parser = subparsers.add_parser("trace", help="correlate pipeline evidence against run manifest")
    trace_parser.add_argument("--manifest", type=Path, required=True, help="path to manifest.json")
    trace_parser.add_argument("--evidence-dir", type=Path, required=True, help="directory containing stage JSON files")
    trace_parser.add_argument("--json", action="store_true", help="output structured JSON instead of Markdown")
    trace_parser.add_argument("--output", type=Path, help="write report output to file")

    # validate command
    val_parser = subparsers.add_parser("validate", help="validate run manifest structure")
    val_parser.add_argument("--manifest", type=Path, required=True, help="path to manifest.json")

    return parser


def load_evidence_files(evidence_dir: Path) -> dict[str, dict]:
    """Load stage evidence files from directory."""
    evidence: dict[str, dict] = {}
    if not evidence_dir.is_dir():
        raise ProofError(f"Evidence directory not found: {evidence_dir}")

    for p in evidence_dir.glob("*.json"):
        if p.name == "manifest.json":
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            evidence[p.stem] = data
        except Exception as e:
            print(f"Warning: Skipping {p.name}: {e}", file=sys.stderr)

    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "trace":
            if not args.manifest.is_file():
                raise ProofError(f"Manifest file not found: {args.manifest}")

            manifest_data = json.loads(args.manifest.read_text(encoding="utf-8"))
            manifest = RunManifest.from_dict(manifest_data)

            evidence_files = load_evidence_files(args.evidence_dir)
            report_data = correlate_pipeline_evidence(manifest, evidence_files)

            if args.json:
                out = render_json_report(report_data)
            else:
                out = render_markdown_report(report_data)

            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(out, encoding="utf-8")
                print(f"Wrote proof report to {args.output}")
            else:
                print(out, end="")
            return 0

        elif args.command == "validate":
            if not args.manifest.is_file():
                raise ProofError(f"Manifest file not found: {args.manifest}")

            data = json.loads(args.manifest.read_text(encoding="utf-8"))
            manifest = RunManifest.from_dict(data)
            print(f"Validated run manifest: {manifest.run_id} ({manifest.pipeline_route}) - Marker: {manifest.synthetic_marker}")
            return 0

    except ProofError as exc:
        print(f"proofpack error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
