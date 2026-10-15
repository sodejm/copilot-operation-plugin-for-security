#!/usr/bin/env python3
"""Run the public disposable service-validation acceptance journey."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from cops.discovery import run_loopback_service_validation_journey  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run discovery through reporting against seven disposable loopback service families."
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        help="Private directory for the durable acceptance budget ledger (temporary by default).",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.state_dir is not None:
        report = run_loopback_service_validation_journey(args.state_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="cops-service-validation-") as directory:
            report = run_loopback_service_validation_journey(Path(directory))
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
