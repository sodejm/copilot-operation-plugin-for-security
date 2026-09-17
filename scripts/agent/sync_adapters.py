#!/usr/bin/env python3
"""Synchronize generated vendor adapters from PARK's canonical open spine."""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _template_common import DISTRIBUTION_IGNORE, TemplateError, synchronize_claude_skills  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]


def trees_match(left: Path, right: Path) -> bool:
    comparison = filecmp.dircmp(left, right, ignore=["__pycache__", ".DS_Store"])
    if comparison.left_only or comparison.right_only or comparison.funny_files:
        return False
    if any(not filecmp.cmp(left / name, right / name, shallow=False) for name in comparison.common_files):
        return False
    return all(trees_match(left / name, right / name) for name in comparison.common_dirs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift without changing files")
    args = parser.parse_args()
    target = ROOT / ".claude" / "skills"
    try:
        if args.check:
            with tempfile.TemporaryDirectory(prefix="park-adapters-") as temp:
                scratch = Path(temp)
                shutil.copytree(ROOT / ".agents" / "skills", scratch / ".agents" / "skills",
                                ignore=DISTRIBUTION_IGNORE)
                synchronize_claude_skills(scratch)
                expected = scratch / ".claude" / "skills"
                if not target.is_dir() or not trees_match(expected, target):
                    print("error: .claude/skills has drifted; run `make sync-agent-adapters`", file=sys.stderr)
                    return 1
            print("Agent adapters are synchronized.")
            return 0
        synchronize_claude_skills(ROOT)
    except TemplateError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print("Synchronized .claude/skills from .agents/skills.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
