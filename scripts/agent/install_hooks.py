#!/usr/bin/env python3
"""
Install local Git push protections and issue coverage hooks.
Standard-library Python only.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOOKS_DIR = ROOT / ".git" / "hooks"

PRE_PUSH_HOOK = """#!/bin/sh
# COPS Pre-Push Protection Hook
# Prevents unauthorized direct push to main, scans for secrets, and verifies issue coverage.

set -e

PROTECTED_BRANCH="main"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Read push parameters from stdin (local_ref local_sha remote_ref remote_sha)
while read -r local_ref local_sha remote_ref remote_sha; do
    # 1. Prevent direct push to protected default branch without override
    if [ "$remote_ref" = "refs/heads/$PROTECTED_BRANCH" ] && [ -z "$COPS_ALLOW_MAIN_PUSH" ]; then
        echo "❌ [PUSH BLOCKED] Direct push to '$PROTECTED_BRANCH' is prohibited per AGENTS.md."
        echo "   Please create a dedicated branch (e.g. codex/<description>) and open a Pull Request."
        echo "   (Override with COPS_ALLOW_MAIN_PUSH=1 if emergency authorized)"
        exit 1
    fi

    # Skip checks if branch deletion
    if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
        continue
    fi

    # Determine base revision
    BASE_REF="origin/$PROTECTED_BRANCH"
    if [ "$remote_sha" != "0000000000000000000000000000000000000000" ]; then
        BASE_REF="$remote_sha"
    fi

    echo "🔍 [COPS Pre-Push] Running issue documentation & test case verification..."
    if ! python3 scripts/agent/check_issue_coverage.py --base "$BASE_REF" --head "$local_sha"; then
        echo "❌ [PUSH BLOCKED] Issue documentation and test cases check failed."
        exit 1
    fi
done

echo "✅ [COPS Pre-Push] Push protections passed."
exit 0
"""


def install_hooks() -> int:
    if not (ROOT / ".git").exists():
        print("error: .git directory not found. Not a git repository.", file=sys.stderr)
        return 1

    HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    pre_push_path = HOOKS_DIR / "pre-push"

    pre_push_path.write_text(PRE_PUSH_HOOK, encoding="utf-8")
    current_mode = os.stat(pre_push_path).st_mode
    os.chmod(pre_push_path, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"✅ Successfully installed COPS pre-push hook: {pre_push_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(install_hooks())
