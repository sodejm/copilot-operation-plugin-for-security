#!/usr/bin/env python3
"""Run deterministic COPS service laboratory acceptance paths."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cops.laboratory.service_lab import ServiceLaboratory, probe_isolated_runtime


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("offline", "process", "isolation-readiness"),
        default="offline",
    )
    parser.add_argument("--profile", choices=("vulnerable", "corrected"), default="vulnerable")
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    parser.add_argument(
        "--require-isolation",
        action="store_true",
        help="Fail unless a verified isolated runtime is reported",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.require_isolation:
        readiness = probe_isolated_runtime().to_dict()
        if readiness.get("verified") is not True:
            print(json.dumps({"status": "blocked", "isolation": readiness}, indent=2, sort_keys=True))
            return 2
    if args.mode == "isolation-readiness":
        result: dict[str, Any] = probe_isolated_runtime().to_dict()
    else:
        laboratory = ServiceLaboratory()
        report = (
            laboratory.run_offline_playback()
            if args.mode == "offline"
            else laboratory.run_process_acceptance(args.profile)
        )
        result = report.to_dict()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    isolation = result.get("isolation", result)
    if args.require_isolation and isolation.get("verified") is not True:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
