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
    except (CatalogError, ValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    parser.error(f"unsupported command: {args.command}")
    return 2
