"""CLI interface for COPS capability and package diagnostics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .runner import run_diagnostics


def build_diagnostics_parser(subparsers: argparse._SubParsersAction[Any]) -> argparse.ArgumentParser:
    """Build the diagnostics sub-parser for cops CLI."""
    parser = subparsers.add_parser(
        "diagnostics",
        help="Run comprehensive capability, tool prerequisite, and package diagnostics.",
        description="Inspect package readiness, verify runtime tool prerequisites, and audit capability truth.",
    )
    parser.add_argument(
        "--package",
        "-p",
        metavar="PACKAGE_ID",
        default=None,
        help="Focus diagnostics on a single plugin package ID (e.g. offensive-engagement-workbench).",
    )
    parser.add_argument(
        "--tools",
        "-t",
        action="store_true",
        help="Run tool prerequisite and host platform diagnostics only.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce strict mode: fail if any optional tool is missing or package is degraded.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    return parser


ROOT: Path = Path(__file__).resolve().parents[2]


def command_diagnostics(
    args: argparse.Namespace | None = None,
    root: Path | None = None,
    *,
    package: str | None = None,
    tools: bool = False,
    strict: bool = False,
    as_json: bool = False,
) -> int:
    """Execute diagnostics CLI command."""
    if root is None:
        root = ROOT

    package_id = package if package is not None else (getattr(args, "package", None) if args else None)
    tools_only = tools if tools else (getattr(args, "tools", False) if args else False)
    strict_mode = strict if strict else (getattr(args, "strict", False) if args else False)
    use_json = as_json if as_json else (getattr(args, "json", False) if args else False)

    report = run_diagnostics(
        root=root,
        package_id=package_id,
        tools_only=tools_only,
        strict=strict_mode,
    )

    if use_json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.all_ready else 1

    # Human-readable terminal output
    print("=== COPS Capability & Package Diagnostics ===")
    print(f"Timestamp:           {report.timestamp}")
    print(f"Platform:            {report.system.os} ({report.system.distribution}) on {report.system.architecture}")
    print(f"Python Runtime:      {report.system.python_version} ({'supported' if report.system.is_supported else 'UNSUPPORTED'})")
    print()

    print("--- Tool Prerequisites Matrix ---")
    tool_rows = []
    for t in report.tools:
        status_marker = "✓" if t.status == "available" else ("!" if t.status == "version_mismatch" else "✗")
        tool_rows.append((t.tool, t.status, t.installed_version or "none", t.minimum_version, status_marker))

    for name, stat, inst, req, marker in tool_rows:
        print(f"  [{marker}] {name:<14} {stat:<18} installed: {inst:<10} required: >={req}")

    if not tools_only and report.packages:
        print()
        print("--- Plugin Package Workflows ---")
        for p in report.packages:
            p_marker = "✓" if p.status == "ready" else ("!" if p.status == "degraded" else "✗")
            print(f"  [{p_marker}] {p.package_id:<32} {p.status:<10} category: {p.category:<24} skills: {p.skills_count}")

    print()
    print("--- Capability Reconciliation ---")
    cap_marker = "✓" if report.capability_truth_passed else "✗"
    print(f"  [{cap_marker}] Total Audited Capabilities: {report.capability_count} (Truth-in-advertising: {'Passed' if report.capability_truth_passed else 'FAILED'})")

    print()
    if report.all_ready:
        print("[PASSED] All evaluated capability diagnostics satisfied.")
        return 0
    else:
        print("[FAILED] One or more required diagnostics failed.", file=sys.stderr)
        return 1
