#!/usr/bin/env python3
"""Validate, inspect, or explicitly install cataloged plugin tool prerequisites."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cops.catalog import load_json, plugin_records  # noqa: E402
from cops.prerequisites import (  # noqa: E402
    PrerequisiteError, install_command, process_tools, validate_prerequisites,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", help="catalog plugin ID; default: all plugins")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate", action="store_true", help="validate declarations only")
    mode.add_argument("--check", action="store_true", help="report missing tools without installing")
    mode.add_argument("--dry-run", action="store_true", help="show install commands without running them")
    mode.add_argument("--install", action="store_true", help="install missing tools with a package manager")
    args = parser.parse_args()
    try:
        records = plugin_records(ROOT)
        if args.plugin:
            records = [record for record in records if record.id == args.plugin]
            if not records:
                raise PrerequisiteError(f"unknown plugin: {args.plugin}")
        selected: list[tuple[str, list[dict]]] = []
        for record in records:
            location = f"{record.path}/com.sodejm.copse/prerequisites.json"
            document = load_json(ROOT / location, ROOT)
            tools = validate_prerequisites(document, location)
            selected.append((record.id, tools))
        if args.install or args.dry_run:
            for _, tools in selected:
                for tool in tools:
                    if not shutil.which(tool["command"]):
                        install_command(tool, sys.platform)
        unavailable: list[str] = []
        for plugin_id, tools in selected:
            if not args.validate:
                missing = process_tools(tools, install=args.install, dry_run=args.dry_run)
                unavailable.extend(f"{plugin_id}: {name}" for name in missing)
        if unavailable:
            print("Missing tools: " + ", ".join(unavailable), file=sys.stderr)
            return 0 if args.dry_run else 1
        print("Prerequisite declarations are valid" if args.validate else "Prerequisites satisfied")
        return 0
    except (PrerequisiteError, ValueError) as error:
        print(f"prerequisite error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
