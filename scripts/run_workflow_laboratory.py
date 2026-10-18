#!/usr/bin/env python3
"""Run the authorized IOC-to-hunt-to-containment service laboratory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from cops.laboratory.workflow_lab import (  # noqa: E402
    IsolationRequiredError,
    run_workflow_service_laboratory,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Exercise an authorized IOC hunt and containment against disposable local TCP services."
    )
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--mode", choices=("success", "failure", "cancellation"), default="success")
    parser.add_argument("--run-id")
    parser.add_argument(
        "--require-isolation",
        action="store_true",
        help="fail before creating state unless an isolation boundary is verified",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_workflow_service_laboratory(
            args.state_directory,
            mode=args.mode,
            require_isolation=args.require_isolation,
            run_id=args.run_id,
        )
    except IsolationRequiredError as error:
        print(
            json.dumps(
                {
                    "schema_version": "cops.workflow-service-laboratory-blocked/v1",
                    "status": "blocked",
                    "reason": str(error),
                    "isolation": error.probe.to_dict(),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
