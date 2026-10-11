#!/usr/bin/env python3
"""Classify a bounded local Linux privilege-boundary export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import ContractError, MAX_INPUT_BYTES, load_report_bytes  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="local v1 JSON export")
    args = parser.parse_args(argv)
    try:
        with args.export.open("rb") as stream:
            report = load_report_bytes(stream.read(MAX_INPUT_BYTES + 1))
    except (OSError, ContractError) as exc:
        error = "invalid or unavailable local export" if isinstance(exc, OSError) else str(exc)
        parser.exit(2, f"error: {error}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
