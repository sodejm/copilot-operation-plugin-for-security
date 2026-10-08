#!/usr/bin/env python3
"""Deterministic demo for COPS Offensive Engagement Workbench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from offensive_engagement_workbench.core import run_engagement_plan_workflow  # noqa: E402


def _parse_tool_versions(values: list[str]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError("tool versions must use TOOL=VERSION")
        tool, version = (part.strip() for part in value.split("=", 1))
        if not tool or not version:
            raise argparse.ArgumentTypeError("tool versions require non-empty TOOL and VERSION")
        existing = versions.get(tool)
        if existing is not None and existing != version:
            raise argparse.ArgumentTypeError(f"conflicting versions supplied for {tool!r}")
        versions[tool] = version
    return versions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tool-version",
        action="append",
        required=True,
        metavar="TOOL=VERSION",
        help="independently measured exact version for a selected tool (repeatable)",
    )
    args = parser.parse_args(argv)

    manifest_path = PACKAGE_ROOT / "fixtures" / "synthetic" / "engagement.json"
    try:
        tool_versions = _parse_tool_versions(args.tool_version)
    except argparse.ArgumentTypeError as err:
        parser.error(str(err))
    result = run_engagement_plan_workflow(
        manifest_path,
        root=REPO_ROOT,
        tool_versions=tool_versions,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
