#!/usr/bin/env python3
"""Print a deterministic offline attack surface plan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_surface_planner.core import GateError, analyze, canonical  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="local signed-off scope manifest")
    args = parser.parse_args()
    try:
        sys.stdout.write(canonical(analyze(args.manifest)))
    except GateError as error:
        print(f"input gate: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
