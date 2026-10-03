"""Operator-first command line for discovering and exercising COPS plugins."""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from .catalog import ROOT, CatalogError, PluginRecord, find_plugin, plugin_records, validate_declared_command
from .coverage import (
    CoverageError,
    evaluate_coverage_gaps,
    generate_attack_flow,
    generate_coverage_matrix,
    load_attack_coverage,
    load_attack_reference,
    render_gap_report_markdown,
    review_coverage_freshness,
)
from .validation import ValidationError, generate_marketplaces, validate_repository


def _print_command(command: Sequence[str]) -> None:
    print("+ " + shlex.join(command), flush=True)


def _run_definition(
    definition: dict[str, Any],
    record: PluginRecord,
    *,
    root: Path,
) -> int:
    command, timeout = validate_declared_command(definition, record, root)
    _print_command(command)
    try:
        result = subprocess.run(command, cwd=root, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"error: {record.id} command timed out after {timeout} seconds", file=sys.stderr)
        return 124
    return result.returncode


def _select(plugin_ids: list[str], root: Path) -> list[PluginRecord]:
    if not plugin_ids:
        return plugin_records(root)
    return [find_plugin(plugin_id, root) for plugin_id in plugin_ids]


def command_list(root: Path = ROOT) -> int:
    records = validate_repository(root)
    header = ("PLUGIN", "CATEGORY", "MATURITY", "OFFLINE", "HOST", "LIVE")
    rows = [
        (
            record.id,
            record.primary_category,
            record.maturity,
            record.support["offline_workflow"],
            record.support["host_installation"],
            record.support["live_integration"],
        )
        for record in records
    ]
    widths = [max(len(row[index]) for row in [header, *rows]) for index in range(len(header))]
    print("  ".join(value.ljust(widths[index]) for index, value in enumerate(header)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))
    return 0


def command_info(plugin_id: str, root: Path = ROOT) -> int:
    validate_repository(root)
    record = find_plugin(plugin_id, root)
    document = {
        "id": record.id,
        "display_name": record.name,
        "version": record.version,
        "category": record.primary_category,
        "maturity": record.maturity,
        "summary": record.package["summary"],
        "support": record.support,
        "limitations": record.package["limitations"],
        "demo": record.package["demo"]["description"],
        "path": record.path,
    }
    print(json.dumps(document, indent=2, ensure_ascii=False))
    return 0


def command_doctor(*, contributor: bool, root: Path = ROOT) -> int:
    missing: list[str] = []
    print(f"COPS root: {root}")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    if sys.version_info < (3, 11):
        missing.append("Python 3.11 or newer")
    try:
        records = validate_repository(root)
        print(f"Catalog: {len(records)} package(s), generated indexes current")
    except CatalogError as error:
        missing.append(f"repository contract ({error})")

    if contributor:
        for module in ("pytest", "pytest_bdd"):
            available = importlib.util.find_spec(module) is not None
            print(f"{module}: {'installed' if available else 'MISSING (test dependency)'}")
            if not available:
                missing.append(module)
        for command, required in (("git", True), ("make", False), ("gh", False)):
            location = shutil.which(command)
            print(f"{command}: {location or ('MISSING (required)' if required else 'not installed (optional)')}")
            if required and not location:
                missing.append(command)

    if missing:
        print("Not ready: " + "; ".join(missing), file=sys.stderr)
        if contributor:
            print("Install contributor dependencies with: python3 -m pip install -r requirements.txt")
        return 1
    mode = "contributor checks" if contributor else "offline plugin use"
    print(f"Environment is ready for {mode}.")
    print("Host installation and live-service behavior remain separate evidence gates.")
    return 0


def command_validate(plugin_ids: list[str], root: Path = ROOT) -> int:
    validate_repository(root)
    records = _select(plugin_ids, root)
    print("Validated package contracts: " + ", ".join(record.id for record in records))
    print("This is structural validation; it does not prove host installation or live integrations.")
    return 0


def command_demo(plugin_id: str, root: Path = ROOT) -> int:
    validate_repository(root)
    record = find_plugin(plugin_id, root)
    print(record.package["demo"]["description"])
    return _run_definition(record.package["demo"], record, root=root)


def command_check(plugin_ids: list[str], root: Path = ROOT) -> int:
    validate_repository(root)
    records = _select(plugin_ids, root)
    failures: list[str] = []
    for record in records:
        print(f"\n[{record.id}]", flush=True)
        for definition in record.package["validation"]:
            name = str(definition["name"])
            print(f"-- {name}", flush=True)
            if _run_definition(definition, record, root=root) != 0:
                failures.append(f"{record.id}:{name}")
    if failures:
        print("Failed package checks: " + ", ".join(failures), file=sys.stderr)
        return 1
    print(f"\nAll declared checks passed for {len(records)} package(s).")
    return 0


def command_generate(*, check: bool, root: Path = ROOT) -> int:
    validate_repository(root, check_indexes=False)
    changed = generate_marketplaces(root, check=check)
    if check:
        print("Generated host indexes are current.")
    elif changed:
        print("Updated host indexes: " + ", ".join(path.as_posix() for path in changed))
    else:
        print("Generated host indexes already current.")
    return 0


def command_coverage(
    *,
    matrix: bool = False,
    output: Path | None = None,
    check: bool = False,
    gaps: bool = False,
    profile_path: Path | None = None,
    export_flow: str | None = None,
    output_flow: Path | None = None,
    as_json: bool = False,
    root: Path = ROOT,
) -> int:
    ref = load_attack_reference(root=root)
    mappings = load_attack_coverage(reference=ref, root=root, strict=True)

    if check:
        freshness = review_coverage_freshness(mappings, ref)
        if freshness["status"] != "fresh":
            print(
                f"error: ATT&CK review findings detected: "
                f"revoked={freshness['revoked_count']}, "
                f"deprecated={freshness['deprecated_count']}, "
                f"version_drift={freshness['version_drift_count']}",
                file=sys.stderr,
            )
            return 1
        matrix_file = root / "docs" / "COVERAGE_MATRIX.md"
        if not matrix_file.is_file():
            print(f"error: Coverage matrix file missing: {matrix_file}", file=sys.stderr)
            return 1
        expected_matrix = generate_coverage_matrix(mappings, ref)
        actual_matrix = matrix_file.read_text(encoding="utf-8")
        if actual_matrix.strip() != expected_matrix.strip():
            print(
                f"error: {matrix_file} is out of date with catalog/attack_coverage.json; "
                f"run 'python3 -m cops coverage --matrix --output docs/COVERAGE_MATRIX.md'",
                file=sys.stderr,
            )
            return 1
        print("MITRE ATT&CK coverage mappings, reference data, and matrix are valid and synchronized.")
        return 0

    if gaps:
        env_profile = None
        if profile_path is not None:
            profile_file = (root / profile_path) if not profile_path.is_absolute() else profile_path
            if not profile_file.is_file():
                print(f"error: profile file not found: {profile_file}", file=sys.stderr)
                return 1
            env_profile = json.loads(profile_file.read_text(encoding="utf-8"))
        gap_data = evaluate_coverage_gaps(mappings, ref, environment_profile=env_profile)
        if as_json:
            print(json.dumps(gap_data, indent=2))
        else:
            print(render_gap_report_markdown(gap_data))
        return 0

    if export_flow:
        flow_data = generate_attack_flow(export_flow, mappings=mappings, reference=ref)
        if output_flow is not None:
            out_path = (root / output_flow) if not output_flow.is_absolute() else output_flow
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(flow_data, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote Attack Flow bundle to {output_flow}")
        else:
            print(json.dumps(flow_data, indent=2))
        return 0

    # Default action: render matrix
    text = generate_coverage_matrix(mappings, ref)
    if output is not None:
        out_path = (root / output) if not output.is_absolute() else output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
        print(f"Wrote coverage matrix to {output}")
    else:
        print(text)
    return 0


def command_contract_validate(file_path: Path, contract_type: str | None = None) -> int:
    from .contracts import ContractError, validate_contract
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        validate_contract(data, contract_type)
        print(f"Contract valid ({data.get('schema_version')}): {file_path}")
        return 0
    except (json.JSONDecodeError, ContractError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def command_contract_transition(current: str, target: str, contract_type: str) -> int:
    from .contracts import ContractError, validate_transition
    try:
        validate_transition(current, target, contract_type)
        print(f"Valid transition for {contract_type}: {current} -> {target}")
        return 0
    except ContractError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m cops",
        description="Discover, validate, and safely exercise COPS cybersecurity plugins.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list cataloged plugins and support evidence")
    info = subparsers.add_parser("info", help="show one plugin's purpose and evidence boundaries")
    info.add_argument("plugin_id")
    doctor = subparsers.add_parser("doctor", help="check the local runtime and repository contract")
    doctor.add_argument("--contributor", action="store_true", help="also require test dependencies and Git")
    validate = subparsers.add_parser("validate", help="validate package and marketplace contracts")
    validate.add_argument("plugin_ids", nargs="*")
    demo = subparsers.add_parser("demo", help="run one package's safe, offline demonstration")
    demo.add_argument("plugin_id")
    check = subparsers.add_parser("check", help="run package-declared deterministic checks")
    check.add_argument("plugin_ids", nargs="*")
    generate = subparsers.add_parser("generate", help="generate host indexes from the catalog")
    generate.add_argument("--check", action="store_true", help="fail instead of writing when indexes are stale")

    cov_parser = subparsers.add_parser("coverage", help="inspect ATT&CK coverage, gap analysis, and Attack Flow")
    cov_parser.add_argument("--matrix", action="store_true", help="render the Markdown coverage matrix")
    cov_parser.add_argument("--output", type=Path, help="write coverage matrix to file")
    cov_parser.add_argument("--check", action="store_true", help="validate mappings and check matrix freshness")
    cov_parser.add_argument("--gaps", action="store_true", help="run telemetry and analytics gap analysis")
    cov_parser.add_argument("--profile", type=Path, help="environment profile for gap analysis")
    cov_parser.add_argument("--export-flow", choices=["azure-identity", "m365-compromise"], help="export STIX 2.1 Attack Flow bundle")
    cov_parser.add_argument("--output-flow", type=Path, help="write Attack Flow bundle to file")
    cov_parser.add_argument("--json", action="store_true", help="output structured JSON")

    route_p = subparsers.add_parser("route", help="route a security task to the optimal specialist profile")
    route_p.add_argument("query", help="natural language task description or request")
    route_p.add_argument("--critical", action="store_true", help="force critical classification (triad)")
    route_p.add_argument("--authorize", action="store_true", help="trigger authorization gate if required")
    route_p.add_argument("--scope", nargs="+", help="target scope identifiers for authorization")
    route_p.add_argument("--action", help="action name for authorization")
    route_p.add_argument("--json", action="store_true", help="output structured JSON")

    spec_p = subparsers.add_parser("specialists", help="list all specialist cybersecurity agent profiles")
    spec_p.add_argument("--json", action="store_true", help="output structured JSON")

    contract_p = subparsers.add_parser("contract", help="validate and transition operational contracts")
    contract_sub = contract_p.add_subparsers(dest="contract_command", required=True)
    c_val = contract_sub.add_parser("validate", help="validate an operational contract file")
    c_val.add_argument("file", type=Path, help="path to contract JSON file")
    c_val.add_argument("--type", choices=["engagement", "scenario", "action_plan", "run_result", "finding"], help="explicit contract type")

    c_trans = contract_sub.add_parser("transition", help="validate a lifecycle transition")
    c_trans.add_argument("current", help="current lifecycle state")
    c_trans.add_argument("target", help="target lifecycle state")
    c_trans.add_argument("--type", choices=["engagement", "action_plan"], default="engagement", help="contract type")

    return parser


def main(argv: list[str] | None = None, *, root: Path = ROOT) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            return command_list(root)
        if args.command == "info":
            return command_info(args.plugin_id, root)
        if args.command == "doctor":
            return command_doctor(contributor=args.contributor, root=root)
        if args.command == "validate":
            return command_validate(args.plugin_ids, root)
        if args.command == "demo":
            return command_demo(args.plugin_id, root)
        if args.command == "check":
            return command_check(args.plugin_ids, root)
        if args.command == "generate":
            return command_generate(check=args.check, root=root)
        if args.command == "coverage":
            return command_coverage(
                matrix=args.matrix,
                output=args.output,
                check=args.check,
                gaps=args.gaps,
                profile_path=args.profile,
                export_flow=args.export_flow,
                output_flow=args.output_flow,
                as_json=args.json,
                root=root,
            )
        if args.command == "route":
            from .routing.cli import command_route
            return command_route(args)
        if args.command == "specialists":
            from .routing.cli import command_list as spec_list
            return spec_list(args)
        if args.command == "contract":
            if args.contract_command == "validate":
                return command_contract_validate(args.file, args.type)
            if args.contract_command == "transition":
                return command_contract_transition(args.current, args.target, args.type)
    except (CatalogError, ValidationError, CoverageError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    parser.error(f"unsupported command: {args.command}")
    return 2
