#!/usr/bin/env python3
"""Install the committed COPS commit and push hooks."""

import subprocess
import sys
from pathlib import Path


def install_hooks() -> int:
    """Use the same reviewed installer as the documented local push gate."""
    root = Path(__file__).resolve().parents[2]
    return subprocess.call([sys.executable, "tools/push_gate/gate.py", "install", *sys.argv[1:]], cwd=root)


if __name__ == "__main__":
    raise SystemExit(install_hooks())
