#!/usr/bin/env python3
"""Plan, dry run, and execute fixture-only incident actions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from incident_response.core import ActionError, build_plan, dry_run, execute, load_json, save_fixture


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    for name in ("action", "tenant", "target", "expires-at", "nonce", "approver-assertion"):
        plan.add_argument(f"--{name}", required=True)
    dry = commands.add_parser("dry-run")
    dry.add_argument("plan", type=Path)
    dry.add_argument("fixture", type=Path)
    run = commands.add_parser("execute")
    run.add_argument("plan", type=Path)
    run.add_argument("receipt", type=Path)
    run.add_argument("fixture", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            result = build_plan(action=args.action, tenant=args.tenant, target=args.target,
                                expires_at=args.expires_at, nonce=args.nonce,
                                approver_assertion=args.approver_assertion)
        elif args.command == "dry-run":
            result = dry_run(load_json(args.plan), load_json(args.fixture))
        else:
            fixture = args.fixture
            updated, result = execute(load_json(args.plan), load_json(args.receipt), load_json(fixture))
            save_fixture(fixture, updated)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (ActionError, OSError, ValueError) as error:
        print(f"incident response rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
