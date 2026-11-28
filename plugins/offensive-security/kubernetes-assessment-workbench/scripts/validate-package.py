#!/usr/bin/env python3
"""Run the package's focused offline behavior checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]


def main() -> int:
    tests = PACKAGE / "tests"
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(tests), "-v"], cwd=ROOT, check=False
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
