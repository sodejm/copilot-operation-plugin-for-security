#!/usr/bin/env python3
"""Deterministic demo for COPS Offensive Engagement Workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from offensive_engagement_workbench.core import run_engagement_plan_workflow  # noqa: E402


def main() -> int:
    manifest_path = PACKAGE_ROOT / "fixtures" / "synthetic" / "engagement.json"
    result = run_engagement_plan_workflow(manifest_path, root=REPO_ROOT)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
