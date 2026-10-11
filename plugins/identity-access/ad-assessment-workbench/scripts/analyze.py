#!/usr/bin/env python3
"""Run the offline AD graph analyzer on a local export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adwb import InventoryError, analyze, load_export  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="Local, explicitly scoped JSON export")
    args = parser.parse_args()
    try:
        report = analyze(load_export(args.export))
    except (InventoryError, OSError) as error:
        code = error.code if isinstance(error, InventoryError) else "invalid_file"
        print(json.dumps({"error": code}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
