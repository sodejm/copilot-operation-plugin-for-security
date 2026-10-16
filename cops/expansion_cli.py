"""Operator interfaces for offline expansion features and pure previews."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_bounded_json(path: Path, *, limit: int = 4_194_304) -> dict[str, Any]:
    """Read one bounded JSON object without echoing potentially sensitive input."""
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input_size_limit")
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError("invalid_input_json") from None
    if not isinstance(value, dict):
        raise ValueError("input_must_be_object")
    return value


def register_expansion_commands(commands: Any) -> None:
    from .assessments.__main__ import add_assessment_arguments
    from .web_api.cli import build_web_api_parser

    explain = commands.add_parser("explain", help="preview routing and authorization without execution")
    explain.add_argument("query")
    explain.add_argument("--json", action="store_true")
    explain.add_argument("--workspace", type=Path, help="collect bounded local context descriptors")
    assess = commands.add_parser("assess", help="assess bounded offline artifacts")
    add_assessment_arguments(assess)

    telemetry = commands.add_parser("telemetry", help="import bounded telemetry artifacts")
    telemetry_commands = telemetry.add_subparsers(dest="telemetry_command", required=True)
    evtx = telemetry_commands.add_parser("import-evtx", help="import a hash-bound clean Sysmon EVTX export")
    evtx.add_argument("--input", type=Path, required=True)
    evtx.add_argument("--sha256", required=True, help="expected source SHA-256 from the evidence manifest")
    evtx.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
    evtx.add_argument("--max-records", type=int, default=4096)
    evtx.add_argument("--deadline", type=float, default=10.0)

    report = commands.add_parser("report", help="export evidence-aware developer reports")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    export = report_commands.add_parser("export")
    export.add_argument("--input", type=Path, required=True)
    export.add_argument("--format", choices=("sarif", "junit", "pr-markdown"), required=True)
    export.add_argument("--output", type=Path)
    export.add_argument("--repository-root", type=Path)
    export.add_argument("--revision")
    export.add_argument("--anchors", type=Path, help="JSON object containing an anchors array")

    workflow = commands.add_parser("workflow", help="validate, preview, or play back typed workflows")
    workflow_commands = workflow.add_subparsers(dest="workflow_command", required=True)
    workflow_commands.add_parser("list")
    workflow_commands.add_parser("validate")
    playback = workflow_commands.add_parser("playback", help="offline evidence playback; no active connectors")
    playback.add_argument("workflow_id")
    inputs = playback.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--profile", help="registered fixture profile")
    inputs.add_argument("--input", type=Path, help="typed workflow inputs")
    playback.add_argument("--run-id", default="offline-playback")
    preview = workflow_commands.add_parser("preview", help="describe workflow stages without state changes")
    preview.add_argument("workflow_id")
    preview.add_argument("--json", action="store_true")
    build_web_api_parser(commands.add_parser("web-api", help="inventory and bounded API replay"))


def _workflow_preview(definition: Any) -> dict[str, Any]:
    # Definitions are validated before metadata is exposed. No runner, worker,
    # approval store, or connector is constructed on this path.
    value = definition.to_dict()
    return {
        "version": "cops.workflow-preview/v1",
        "status": "preview",
        "workflow_id": definition.workflow_id,
        "definition_digest": definition.definition_digest,
        "specialists": list(dict.fromkeys(stage["action"]["specialist_id"] for stage in value["stages"])),
        "actions": [{
            "stage_id": stage["stage_id"],
            "action": stage["action"]["action"],
            "target": stage["action"]["target"],
            "dependencies": stage["depends_on"],
            "effects": stage["action"].get("side_effects", "unknown"),
            "destinations": stage["action"].get("egress_policy", "unknown"),
            "expected_evidence": stage["action"].get("expected_evidence", "unknown"),
            "authorization": "new bound ActionPlan authorization required for execution",
            "noise": "unknown",
        } for stage in value["stages"]],
        "budget": value["budget"],
        "side_effects_performed": False,
        "approvals_consumed": False,
        "connectors_invoked": False,
        "workers_started": False,
        "state_written": False,
    }


def dispatch_expansion_command(args: argparse.Namespace, root: Path) -> int:
    try:
        if args.command == "telemetry":
            from .adapters.evtx import import_evtx

            print(json.dumps(import_evtx(args.input, expected_sha256=args.sha256,
                                        max_bytes=args.max_bytes, max_records=args.max_records,
                                        deadline=args.deadline), indent=2, sort_keys=True))
            return 0
        if args.command == "web-api":
            from .web_api.cli import command_web_api

            return command_web_api(args, root=root)
        if args.command == "assess":
            from .assessments.__main__ import command_assess

            return command_assess(args)
        if args.command == "explain":
            from .context import collect_repository_context
            from .preview import build_execution_preview, render_preview
            from .routing import route_request

            decision = route_request(args.query, registry_path=root / "agents/registry.json")
            preview = build_execution_preview(decision).to_dict()
            document = {"routing": decision.to_dict(), "preview": preview}
            if args.workspace is not None:
                document["context"] = collect_repository_context(args.workspace).to_dict()
            if args.json:
                print(json.dumps(document, indent=2, sort_keys=True))
            else:
                print(render_preview(preview))
                print("Routing: " + decision.status)
                if decision.status != "routed":
                    print("Clarification required; candidate purposes and permissions:")
                    for candidate in decision.to_dict()["ranked_candidates"][:3]:
                        print(json.dumps(candidate, sort_keys=True))
            return 0
        if args.command == "report":
            from .reports import SourceAnchor, export_report

            anchors = ()
            if args.anchors is not None:
                document = load_bounded_json(args.anchors)
                if not isinstance(document.get("anchors"), list):
                    raise ValueError("invalid_source_anchors")
                anchors = tuple(SourceAnchor(**anchor) for anchor in document["anchors"])
            content = export_report(
                load_bounded_json(args.input), format=args.format,
                repository_root=args.repository_root, revision=args.revision, source_anchors=anchors,
            )
            if args.output is None:
                print(content)
            else:
                args.output.write_text(content, encoding="utf-8")
            return 0
        if args.command == "workflow":
            from .preview import render_preview
            from .workflows.playback import (
                load_integrated_workflows, run_fixture_profile, run_offline_playback,
                validate_integrated_workflow_catalog,
            )

            catalog_dir = root / "catalog/workflows"
            if args.workflow_command == "validate":
                document = validate_integrated_workflow_catalog(catalog_dir)
            elif args.workflow_command == "list":
                document = {"workflows": sorted(load_integrated_workflows(catalog_dir))}
            elif args.workflow_command == "preview":
                definitions = load_integrated_workflows(catalog_dir)
                if args.workflow_id not in definitions:
                    raise ValueError("unknown_workflow")
                document = _workflow_preview(definitions[args.workflow_id])
                if not args.json:
                    print(render_preview(document))
                    return 0
            elif args.profile is not None:
                document = run_fixture_profile(args.workflow_id, args.profile, catalog_dir=catalog_dir, run_id=args.run_id)
            else:
                document = run_offline_playback(
                    args.workflow_id, load_bounded_json(args.input), catalog_dir=catalog_dir, run_id=args.run_id,
                )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        raise ValueError("unknown_expansion_command")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        # Library exceptions can contain private input or filesystem paths.
        # Expose only a bounded identifier, never an exception's free-form text.
        import re

        code = getattr(exc, "code", "invalid_request")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            code = "invalid_request"
        print(json.dumps({"error": code}, sort_keys=True), file=sys.stderr)
        return 2
