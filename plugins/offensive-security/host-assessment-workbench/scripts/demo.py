#!/usr/bin/env python3
"""Run the synthetic Linux privilege-boundary import demonstration."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import load_report_bytes  # noqa: E402


def main() -> int:
    cases = {}
    for name in ("positive", "negative", "fixed"):
        fixture = PACKAGE / "fixtures" / "synthetic" / f"host_linux_{name}_v1.json"
        report = load_report_bytes(fixture.read_bytes())
        cases[name] = {
            "source_kind": report["source"]["kind"],
            "counts": report["counts"],
            "coverage": report["coverage"],
        }
    print(json.dumps({"status": "passed", "mode": "offline_import", "cases": cases}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
