#!/usr/bin/env python3
"""Report whether the local environment can validate COPS."""

from __future__ import annotations

import platform
import importlib.util
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    print(f"COPS root: {ROOT}")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    required_missing = []
    if sys.version_info < (3, 11):
        required_missing.append("Python 3.11 or newer")
    for module in ("pytest", "pytest_bdd"):
        available = importlib.util.find_spec(module) is not None
        print(f"{module}: {'installed' if available else 'MISSING (test dependency)'}")
        if not available:
            required_missing.append(module)
    for command, required in (("git", True), ("make", False), ("gh", False)):
        location = shutil.which(command)
        status = location or ("MISSING (required)" if required else "not installed (optional)")
        print(f"{command}: {status}")
        if required and not location:
            required_missing.append(command)
    if required_missing:
        print("Missing requirements: " + ", ".join(required_missing), file=sys.stderr)
        print("Install test dependencies with: python3 -m pip install -r requirements.txt")
        return 1
    print("Environment is ready for COPS checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
