"""CLI subcommands for COPS engagement intake and action planning."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cops.catalog import ROOT

from .errors import EngagementIntakeError
from .intake import create_engagement_contract, validate_engagement_intake
from .planning import build_action_plan


def _parse_tool_versions(values: list[str]) -> dict[str, str]:
    """Parse explicit, independently measured TOOL=VERSION inputs."""
    parsed: dict[str, str] = {}
    for value in values:
        tool, separator, version = value.partition("=")
        tool = tool.strip()
        version = version.strip()
        if not separator or not tool or not version:
            raise EngagementIntakeError("tool versions must use TOOL=VERSION with non-empty values")
        if tool in parsed and parsed[tool] != version:
            raise EngagementIntakeError(f"conflicting exact versions supplied for tool '{tool}'")
        parsed[tool] = version
    return parsed


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
        print(
            json.dumps(
                {
                    "status": "valid",
                    "engagement_id": validated["engagement_id"],
                    "mode": validated.get("mode", "planning"),
                },
                indent=2,
            )
        )
    else:
        print(f"Engagement '{validated['engagement_id']}' is valid ({validated.get('mode', 'planning')} mode).")
        print(
            f"  Targets: {len(validated['scope']['included_targets'])} included, {len(validated['scope'].get('excluded_targets', []))} excluded"
        )
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
            tool_versions=_parse_tool_versions(args.tool_versions),
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
        if summary["budget"]:
            print(
                f"  Budget: {summary['budget']['max_duration_seconds']}s, {summary['budget']['max_output_bytes']} bytes"
            )

    return 0


def _load_json_or_file(source: Any) -> dict[str, Any]:
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    if isinstance(source, Path):
        return json.loads(source.read_text(encoding="utf-8"))
    if isinstance(source, str):
        trimmed = source.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                return json.loads(source)
            except json.JSONDecodeError:
                pass
        try:
            p = Path(source)
            if p.is_file():
                return json.loads(p.read_text(encoding="utf-8"))
        except OSError:
            pass
        return json.loads(source)
    raise ValueError(f"Unsupported source type: {type(source)}")


def command_engagement_handoff(args: argparse.Namespace, root: Path = ROOT) -> int:
    """Handle `cops engagement handoff <propose|accept|review|audit|workflow>`."""
    from cops.contracts.models import SpecialistHandoff
    from cops.routing.handoff import (
        HandoffError,
        accept_specialist_handoff,
        audit_and_approve_handoff,
        execute_triad_handoff_workflow,
        propose_specialist_handoff,
        review_with_skeptic,
    )

    cmd = getattr(args, "handoff_command", None)
    agents_reg_path = root / "agents" / "registry.json"

    try:
        if cmd == "propose":
            eng_doc = _load_json_or_file(args.engagement)
            plan_doc = _load_json_or_file(args.plan)
            req_caps = None
            if getattr(args, "capabilities", None):
                if isinstance(args.capabilities, str):
                    req_caps = [c.strip() for c in args.capabilities.split(",") if c.strip()]
                elif isinstance(args.capabilities, list):
                    req_caps = args.capabilities
            handoff = propose_specialist_handoff(
                engagement=eng_doc,
                action_plan=plan_doc,
                task_description=args.task,
                sender_id=getattr(args, "planner", None) or getattr(args, "sender", "secops-lead"),
                specialist_id=args.specialist,
                workflow_skill_id=getattr(args, "workflow_skill", None),
                capability_id=getattr(args, "capability", None),
                required_capabilities=req_caps,
                registry_path=agents_reg_path,
            )
            result_doc = handoff.to_dict()

        elif cmd == "accept":
            handoff_doc = _load_json_or_file(args.handoff)
            handoff = SpecialistHandoff.from_dict(handoff_doc)
            accept_specialist_handoff(handoff, specialist_id=args.specialist, registry_path=agents_reg_path)
            result_doc = handoff.to_dict()

        elif cmd == "review":
            handoff_doc = _load_json_or_file(args.handoff)
            handoff = SpecialistHandoff.from_dict(handoff_doc)
            review_with_skeptic(
                handoff,
                skeptic_id=args.skeptic,
                evidence_envelopes=getattr(args, "evidence", None),
                findings=getattr(args, "findings", None),
                registry_path=agents_reg_path,
            )
            result_doc = handoff.to_dict()

        elif cmd == "audit":
            handoff_doc = _load_json_or_file(args.handoff)
            plan_doc = _load_json_or_file(args.plan)
            handoff = SpecialistHandoff.from_dict(handoff_doc)
            audit_and_approve_handoff(
                handoff,
                auditor_id=args.auditor,
                approved_action_plan=plan_doc,
                registry_path=agents_reg_path,
            )
            result_doc = handoff.to_dict()

        elif cmd == "workflow":
            eng_doc = _load_json_or_file(args.engagement)
            plan_doc = _load_json_or_file(args.plan)
            handoff = execute_triad_handoff_workflow(
                engagement=eng_doc,
                action_plan=plan_doc,
                task_description=args.task,
                planner_id=getattr(args, "planner", None) or getattr(args, "sender", "secops-lead"),
                specialist_id=args.specialist,
                workflow_skill_id=getattr(args, "workflow_skill", None),
                capability_id=getattr(args, "capability", None),
                registry_path=agents_reg_path,
            )
            result_doc = handoff.to_dict()
        else:
            print(f"error: unknown handoff command: {cmd}", file=sys.stderr)
            return 2

    except HandoffError as err:
        print(f"error: handoff failed: {err}", file=sys.stderr)
        return 2
    except Exception as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    rendered = json.dumps(result_doc, indent=2, sort_keys=True)
    if getattr(args, "output", None):
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(rendered + "\n", encoding="utf-8")
        print(f"Handoff written to {out_p}")
    elif getattr(args, "json", False):
        print(rendered)
    else:
        print(
            f"Handoff {result_doc['handoff_id']} status: {result_doc['status']} (Approval: {result_doc['approval_status']})"
        )
        print(f"  Sender:    {result_doc['sender']['role']} [{result_doc['sender']['identifier']}]")
        print(f"  Recipient: {result_doc['recipient']['role']} [{result_doc['recipient']['specialist_id']}]")
        print(f"  Task:      {result_doc['task']['task_description']}")
        print(f"  Target:    {result_doc['task']['target']}")
        print(f"  Digest:    {result_doc['material_plan_digest']}")

    return 0
