# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
#!/usr/bin/env python3
"""Compatibility wrapper for the contributor environment check."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cops.cli import command_doctor


def main() -> int:
    return command_doctor(contributor=True, root=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
