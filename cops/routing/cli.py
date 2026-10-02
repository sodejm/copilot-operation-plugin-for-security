"""Command-line interface for COPS specialist agent discovery, routing, and authorization."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from cops.authorization import ensure_authorization
from .catalog import get_specialist, load_specialists_registry
from .classifier import route_request


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
    decision = route_request(args.query, force_critical=args.critical)

    authorize = getattr(args, "authorize", False)
    if authorize and decision.interactive_authorization_required:
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
            out = decision.to_dict()
            out["authorization_receipt"] = receipt.to_dict()
            print(json.dumps(out, indent=2))
            return 0

    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
        return 0

    p = decision.primary_profile
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
