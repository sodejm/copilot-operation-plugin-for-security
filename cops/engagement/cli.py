"""CLI subcommands for COPS engagement intake and action planning."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from cops.catalog import ROOT
from cops.contracts.models import Engagement
from .errors import EngagementIntakeError
from .intake import create_engagement_contract, validate_engagement_intake
from .planning import build_action_plan


def command_engagement_create(args: argparse.Namespace) -> int:
    """Handle `cops engagement create`."""
    targets = [t.strip() for t in args.targets.split(",") if t.strip()] if args.targets else []
    exclusions = [e.strip() for e in args.exclusions.split(",") if e.strip()] if args.exclusions else []
    allowed = [a.strip() for a in args.allowed_effects.split(",") if a.strip()] if args.allowed_effects else None
    creds = [c.strip() for c in args.credentials.split(",") if c.strip()] if args.credentials else None

    budget = None
    if args.budget_duration or args.budget_output_bytes:
        dur = args.budget_duration if args.budget_duration else 3600
        bytes_out = args.budget_output_bytes if args.budget_output_bytes else 10485760
        budget = {"max_duration_seconds": dur, "max_output_bytes": bytes_out}

    try:
        engagement = create_engagement_contract(
            name=args.name,
            operator=args.owner,
            included_targets=targets,
            excluded_targets=exclusions,
            started_at=args.start,
            authorized_until_utc=args.until,
            allowed_actions=allowed,
            max_intensity=args.max_intensity,
            emergency_contact=args.emergency_contact,
            safe_mode=not args.no_safe_mode,
            mode=args.mode,
            budget=budget,
            credential_references=creds,
            engagement_id=args.id,
        )
    except EngagementIntakeError as err:
        print(f"error: engagement intake validation failed: {err}", file=sys.stderr)
        return 2

    doc = engagement.to_dict()
    rendered = json.dumps(doc, indent=2, sort_keys=True)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Engagement written to {out_path}")
    else:
        print(rendered)

    return 0


def command_engagement_validate(args: argparse.Namespace) -> int:
    """Handle `cops engagement validate`."""
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"error: file not found: {file_path}", file=sys.stderr)
        return 2

    try:
        raw_doc = json.loads(file_path.read_text(encoding="utf-8"))
        validated = validate_engagement_intake(raw_doc)
    except json.JSONDecodeError as err:
        print(f"error: JSON decode failed for {file_path}: {err}", file=sys.stderr)
        return 2
    except EngagementIntakeError as err:
        print(f"error: engagement validation failed: {err}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"status": "valid", "engagement_id": validated["engagement_id"], "mode": validated.get("mode", "planning")}, indent=2))
    else:
        print(f"Engagement '{validated['engagement_id']}' is valid ({validated.get('mode', 'planning')} mode).")
        print(f"  Targets: {len(validated['scope']['included_targets'])} included, {len(validated['scope'].get('excluded_targets', []))} excluded")
        print(f"  Operator: {validated['operator']}")
        print(f"  Window: {validated['window']['started_at']} -> {validated['window']['authorized_until_utc']}")

    return 0


def command_engagement_plan(args: argparse.Namespace) -> int:
    """Handle `cops engagement plan`."""
    eng_path = Path(args.engagement)
    if not eng_path.is_file():
        print(f"error: engagement file not found: {eng_path}", file=sys.stderr)
        return 2

    try:
        raw_eng = json.loads(eng_path.read_text(encoding="utf-8"))
        plan = build_action_plan(
            engagement=raw_eng,
            scenario=args.scenario,
            target=args.target,
            specialist_id=args.specialist,
            mode=args.mode,
            root=ROOT,
        )
    except json.JSONDecodeError as err:
        print(f"error: JSON decode failed: {err}", file=sys.stderr)
        return 2
    except EngagementIntakeError as err:
        print(f"error: action plan generation failed: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"error: unexpected error generating plan: {err}", file=sys.stderr)
        return 2

    doc = plan.to_dict()
    rendered = json.dumps(doc, indent=2, sort_keys=True)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Action plan written to {out_path}")
    else:
        print(rendered)

    return 0


def command_engagement_info(args: argparse.Namespace) -> int:
    """Handle `cops engagement info`."""
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"error: file not found: {file_path}", file=sys.stderr)
        return 2

    try:
        doc = json.loads(file_path.read_text(encoding="utf-8"))
        validated = validate_engagement_intake(doc)
    except Exception as err:
        print(f"error: failed to read engagement: {err}", file=sys.stderr)
        return 2

    summary = {
        "engagement_id": validated["engagement_id"],
        "name": validated["name"],
        "status": validated["status"],
        "mode": validated.get("mode", "planning"),
        "operator": validated["operator"],
        "targets_count": len(validated["scope"]["included_targets"]),
        "exclusions_count": len(validated["scope"].get("excluded_targets", [])),
        "window": validated["window"],
        "budget": validated.get("budget"),
        "credential_references": validated.get("credential_references", []),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Engagement: {summary['name']} [{summary['engagement_id']}]")
        print(f"  Mode: {summary['mode']}")
        print(f"  Status: {summary['status']}")
        print(f"  Operator: {summary['operator']}")
        print(f"  Window: {summary['window']['started_at']} to {summary['window']['authorized_until_utc']}")
        print(f"  Targets: {summary['targets_count']} in scope, {summary['exclusions_count']} excluded")
        if summary['budget']:
            print(f"  Budget: {summary['budget']['max_duration_seconds']}s, {summary['budget']['max_output_bytes']} bytes")

    return 0
