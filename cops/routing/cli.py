"""Command-line interface for COPS specialist agent discovery, routing, and authorization."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cops.authorization import ensure_authorization

from .catalog import get_specialist, load_specialists_registry
from .classifier import route_request
from .input_kinds import INPUT_KINDS
from .model_advisor import COMPLEXITIES, EFFORTS, TASK_KINDS, ModelCatalogError, advise_models, load_catalog


def add_input_kind_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input-kind",
        choices=INPUT_KINDS,
        action="append",
        help="describe the evidence available for review (repeatable)",
    )


def render_clarification(clarification: dict[str, Any]) -> None:
    print(clarification["question"])
    for option in clarification["options"]:
        print(f"  {option['display_name']} ({option['specialist_id']})")
        print(f"    Purpose: {option['purpose']}")
        if "suggested_input" in option:
            print(f"    Suggested input: {option['suggested_input']}")
        if option["tools"]:
            print(f"    Tools: {', '.join(option['tools'])}")
        permissions = ", ".join(option["required_permissions"]) or "none declared"
        print(f"    Permissions: {permissions}")
    print(f"  Evidence categories: {', '.join(clarification['supported_input_kinds'])}")


def add_model_arguments(parser: argparse.ArgumentParser) -> None:
    """Keep model advice options identical across the two public route CLIs."""
    parser.add_argument("--suggest-model", action="store_true", help="include advisory model and effort requirements")
    parser.add_argument("--model-catalog", type=Path, help="fresh host model catalog JSON (implies --suggest-model)")
    parser.add_argument(
        "--task-kind", choices=TASK_KINDS, default="auto", help="override model advice task classification"
    )
    parser.add_argument("--complexity", choices=COMPLEXITIES, default="auto", help="override model advice complexity")
    parser.add_argument("--current-model", help="exact currently selected host model ID")
    parser.add_argument("--current-effort", choices=EFFORTS, help="currently selected reasoning effort")


def _model_advice(args: argparse.Namespace) -> dict | None:
    catalog_path = getattr(args, "model_catalog", None)
    task_kind = getattr(args, "task_kind", "auto")
    complexity = getattr(args, "complexity", "auto")
    current_model = getattr(args, "current_model", None)
    current_effort = getattr(args, "current_effort", None)
    if not (
        getattr(args, "suggest_model", False)
        or catalog_path
        or task_kind != "auto"
        or complexity != "auto"
        or current_model
        or current_effort
    ):
        return None
    return advise_models(
        args.query,
        catalog=load_catalog(catalog_path) if catalog_path else None,
        task_kind=task_kind,
        complexity=complexity,
        current_model=current_model,
        current_effort=current_effort,
    )


def command_list(args: argparse.Namespace) -> int:
    profiles = load_specialists_registry()
    if args.json:
        print(json.dumps([p.to_dict() for p in profiles], indent=2))
        return 0

    header = ("PROFILE ID", "DOMAIN", "CRITICALITY", "AUTH REQ", "PRIMARY PLUGIN")
    rows = [
        (
            p.id,
            p.domain,
            p.criticality,
            "YES" if p.interactive_authorization_required else "no",
            p.primary_plugin,
        )
        for p in profiles
    ]
    widths = [max(len(row[i]) for row in [header, *rows]) for i in range(len(header))]
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(header)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(val.ljust(widths[i]) for i, val in enumerate(row)))
    return 0


def command_info(args: argparse.Namespace) -> int:
    profile = get_specialist(args.specialist_id)
    if args.json:
        print(json.dumps(profile.to_dict(), indent=2))
        return 0

    print(f"\nProfile ID        : {profile.id}")
    print(f"Display Name      : {profile.display_name}")
    print(f"Domain            : {profile.domain}")
    print(f"Criticality       : {profile.criticality}")
    print(f"Auth Required     : {profile.interactive_authorization_required}")
    print(f"Primary Plugin    : {profile.primary_plugin}")
    print(f"Contract File     : {profile.contract_file}")
    print(f"Skills            : {', '.join(profile.skills)}")
    print(f"Tools             : {', '.join(profile.tools)}")
    if profile.triad_defaults:
        print("Triad Defaults    :")
        print(f"  - Skeptic Profile : {profile.triad_defaults['skeptic_profile_id']}")
        print(f"  - Auditor Profile : {profile.triad_defaults['auditor_profile_id']}")
    print(f"\nDescription:\n  {profile.description}\n")
    return 0


def command_route(args: argparse.Namespace) -> int:
    # Validate untrusted catalog input before any interactive authorization.
    try:
        advice = _model_advice(args)
    except ModelCatalogError as exc:
        print(f"Model advice error: {exc}", file=sys.stderr)
        return 2
    from .detection_quality import route_bundled_review

    input_kinds = tuple(getattr(args, "input_kind", None) or ())
    bundled = route_bundled_review(args.query, force_critical=args.critical)
    if bundled and input_kinds and set(input_kinds) != {"detection-rule"}:
        from .classifier import _clarification
        from .input_kinds import input_guidance

        general = route_request(args.query, force_critical=args.critical, input_kinds=input_kinds)
        candidates = list(bundled.ranked_candidates)
        candidates.extend(c for c in general.ranked_candidates if c.profile.id != bundled.primary_profile.id)
        decision = _clarification(
            args.query,
            candidates,
            "The stated goal and declared evidence do not identify the same single specialist.",
            input_guidance(input_kinds),
            question="Which outcome should the review prioritize?",
        )
    else:
        decision = bundled or route_request(
            args.query, force_critical=args.critical, input_kinds=input_kinds
        )
    out = decision.to_dict()
    if advice is not None:
        out["model_advice"] = advice

    authorize = getattr(args, "authorize", False)
    if authorize and decision.status == "routed" and decision.interactive_authorization_required:
        scope = getattr(args, "scope", None) or ["default-workspace"]
        action = getattr(args, "action", None) or "execute-specialist-assessment"
        receipt = ensure_authorization(
            specialist_id=decision.primary_profile.id,
            action_type=action,
            target_scope=scope,
            allowed_operations=list(decision.primary_profile.skills),
            interactive=True,
        )
        if args.json:
            out["authorization_receipt"] = receipt.to_dict()
            print(json.dumps(out, indent=2))
            return 0

    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    if decision.status == "clarification_required":
        print("\n" + "=" * 65)
        print("  COPS SPECIALIST ROUTING CLARIFICATION")
        print("=" * 65)
        print(f"  Query / Intent     : {decision.query}")
        print(f"  Status             : {decision.status}")
        print(f"  Routing Confidence : {decision.confidence * 100:.1f}%")
        for reason in decision.match_reasons:
            print(f"  Reason             : {reason}")
        if decision.clarification:
            print()
            render_clarification(decision.clarification)
        print("=" * 65 + "\n")
        return 0

    p = decision.primary_profile
    assert p is not None
    print("\n" + "=" * 65)
    print("  COPS SPECIALIST ROUTING DECISION")
    print("=" * 65)
    print(f"  Query / Intent     : {decision.query}")
    print(f"  Selected Profile   : {p.display_name} ({p.id})")
    print(f"  Confidence         : {decision.confidence * 100:.1f}%")
    print(f"  Primary Plugin     : {p.primary_plugin}")
    print(f"  Operational Domain : {p.domain}")
    print(f"  Criticality Level  : {decision.criticality.upper()}")
    print(f"  Interactive Auth   : {'REQUIRED' if decision.interactive_authorization_required else 'Not Required'}")
    print(f"  Recommended Skills : {', '.join(decision.recommended_skills)}")

    print("\n  Matching Rationales:")
    for reason in decision.match_reasons:
        print(f"    * {reason}")

    if advice is not None:
        print(f"\n  Model Advice (advisory only): {advice['status']}")
        print(f"    {advice['task']['reason']}")
        recommendation = advice["recommendation"]
        if recommendation:
            print(f"    Suggested: {recommendation['model_id']} / {recommendation['effort']}")
        print(f"    Current settings: {advice['current']['status']}")
        for model_id, reasons in advice["excluded"].items():
            print(f"    Excluded {model_id}: {', '.join(reasons)}")
        print(f"    Next: {advice['next_action']}")

    if decision.triad_plan:
        tp = decision.triad_plan
        print("\n  [!] CRITICAL TASK DETECTED - TRIAD ORCHESTRATION ASSEMBLED:")
        print(f"    * Primary Specialist : {tp.primary.display_name} ({tp.primary.specialist_id})")
        print(f"    * Domain Skeptic     : {tp.skeptic.display_name} ({tp.skeptic.specialist_id})")
        print(f"    * Evidence Auditor   : {tp.auditor.display_name} ({tp.auditor.specialist_id})")
        print("\n  Triad Handoff Sequence:")
        for step in tp.handoff_steps:
            print(f"    {step}")

    print("=" * 65 + "\n")
    return 0


def command_authorize(args: argparse.Namespace) -> int:
    profile = get_specialist(args.specialist)
    scope = args.scope if args.scope else ["default-target-scope"]
    action = args.action if args.action else "general-assessment"
    allowed_ops = args.ops if args.ops else list(profile.skills)

    receipt = ensure_authorization(
        specialist_id=profile.id,
        action_type=action,
        target_scope=scope,
        allowed_operations=allowed_ops,
        interactive=not args.non_interactive,
    )
    if args.json:
        print(json.dumps(receipt.to_dict(), indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m cops.routing",
        description="COPS Specialist Agent Routing and Authorization CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    list_p = subparsers.add_parser("list", help="List all available specialist agent profiles")
    list_p.add_argument("--json", action="store_true", help="Output JSON format")
    list_p.set_defaults(func=command_list)

    # info
    info_p = subparsers.add_parser("info", help="Get detailed profile information")
    info_p.add_argument("specialist_id", help="Specialist profile ID (e.g. cops-sentinel-kql-engineer)")
    info_p.add_argument("--json", action="store_true", help="Output JSON format")
    info_p.set_defaults(func=command_info)

    # route
    route_p = subparsers.add_parser("route", help="Route a request to the optimal specialist profile")
    route_p.add_argument("query", help="Security task description or natural language query")
    route_p.add_argument("--critical", action="store_true", help="Force critical criticality level (triad)")
    route_p.add_argument("--authorize", action="store_true", help="Trigger authorization gate if required")
    route_p.add_argument("--scope", nargs="+", help="Target scope identifiers for authorization")
    route_p.add_argument("--action", help="Action name for authorization")
    route_p.add_argument("--json", action="store_true", help="Output JSON format")
    add_input_kind_arguments(route_p)
    add_model_arguments(route_p)
    route_p.set_defaults(func=command_route)

    # authorize
    auth_p = subparsers.add_parser("authorize", help="Request or verify interactive authorization")
    auth_p.add_argument("--specialist", required=True, help="Specialist profile ID")
    auth_p.add_argument("--action", required=True, help="Action type to authorize")
    auth_p.add_argument("--scope", nargs="+", required=True, help="Target scope (IPs, domains, tenants)")
    auth_p.add_argument("--ops", nargs="+", help="Allowed operations")
    auth_p.add_argument("--non-interactive", action="store_true", help="Disable interactive prompt")
    auth_p.add_argument("--json", action="store_true", help="Output JSON receipt")
    auth_p.set_defaults(func=command_authorize)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
