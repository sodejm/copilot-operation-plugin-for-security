"""CLI interface for Web Application & API Inventory and Request Replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .importer import (
    import_har,
    import_openapi,
    import_postman,
    import_raw_http,
)
from .models import (
    ApiInventory,
    ApiProtocol,
    ReplayBudget,
    ReplayRequest,
    ReplaySessionReport,
)
from .replay import (
    OfflineSyntheticReplayer,
    execute_replay_session,
    preview_replay_session,
)

_PREVIEW_UNKNOWNS = [
    "Live response status, headers, body, latency, redirects, rate-limit behavior, "
    "authorization behavior, and server-side effects remain unobserved.",
    "Inventory-derived requests may still require runtime parameters or credentials; "
    "this preview does not prove that a request is viable.",
]


def _replay_preview_document(
    *,
    inventory: ApiInventory,
    requests: list[ReplayRequest],
    destinations: list[str],
    budget: ReplayBudget,
    requested_mode: str,
) -> dict[str, Any]:
    """Build the stable, redacted CLI preview without dispatching work."""
    preview = preview_replay_session(
        requests=requests,
        allowed_destinations=destinations,
        budget=budget,
    )
    return {
        "schema_version": "cops.web-api-replay-preview/v1",
        "requested_mode": requested_mode,
        "destinations": {
            "allowed": preview.allowed_destinations,
            "target_hosts": preview.target_hosts,
            "request_urls": [request.url for request in preview.requests],
        },
        "budget": preview.budget.to_dict(),
        "evidence": {
            "inventory_id": inventory.inventory_id,
            "inventory_name": inventory.name,
            "imported_sources": list(inventory.imported_sources),
            "credentials_redacted": inventory.credentials_redacted,
            "prepared_request_count": len(preview.requests),
            "requests": [request.to_dict() for request in preview.requests],
        },
        "effects": {
            "network_requests": 0,
            "workers_started": 0,
            "authorizations_consumed": 0,
            "authentication_sessions_used": 0,
            "files_written": 0,
            "state_changes": [],
        },
        "unknowns_and_noise": list(_PREVIEW_UNKNOWNS),
    }


def _print_replay_preview(preview: dict[str, Any]) -> None:
    """Render a human-readable form of the stable replay preview contract."""
    destinations = preview["destinations"]
    budget = preview["budget"]
    evidence = preview["evidence"]
    effects = preview["effects"]

    print("=== Web API Replay Preview ===")
    print(f"Requested Mode: {preview['requested_mode']}")
    print("Destinations:")
    print(f"  Allowed: {', '.join(destinations['allowed'])}")
    print(f"  Target Hosts: {', '.join(destinations['target_hosts'])}")
    for url in destinations["request_urls"]:
        print(f"  Request URL: {url}")
    print("Budget:")
    for name, value in budget.items():
        print(f"  {name}: {value}")
    print("Evidence:")
    print(f"  Inventory: {evidence['inventory_name']} ({evidence['inventory_id']})")
    print(f"  Imported sources: {', '.join(evidence['imported_sources']) or 'none'}")
    print(f"  Credentials redacted: {evidence['credentials_redacted']}")
    print(f"  Prepared requests: {evidence['prepared_request_count']}")
    for request in evidence["requests"]:
        print(f"  Request: {request['request_id']} {request['method']} {request['url']}")
    print("Effects:")
    print(f"  Network requests: {effects['network_requests']}")
    print(f"  Workers started: {effects['workers_started']}")
    print(f"  Authorizations consumed: {effects['authorizations_consumed']}")
    print(f"  Authentication sessions used: {effects['authentication_sessions_used']}")
    print(f"  Files written: {effects['files_written']}")
    state_changes = ", ".join(effects["state_changes"]) or "none"
    print(f"  State changes: {state_changes}")
    print("Unknowns / Noise:")
    for unknown in preview["unknowns_and_noise"]:
        print(f"  - {unknown}")


def build_web_api_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Build parser for web-api subcommands."""
    subparsers = parser.add_subparsers(dest="web_api_command", required=True)

    # 1. inventory subcommand
    inv_parser = subparsers.add_parser(
        "inventory",
        help="Import API traffic/definitions and generate sanitized API inventory.",
    )
    inv_parser.add_argument("--har", help="Path to HAR 1.2 traffic capture file.")
    inv_parser.add_argument("--openapi", help="Path to OpenAPI 3.x or Swagger 2.0 definition file.")
    inv_parser.add_argument("--postman", help="Path to Postman Collection v2.0/v2.1 file.")
    inv_parser.add_argument("--raw", help="Path to raw HTTP request text file.")
    inv_parser.add_argument("--name", default="", help="Name of the API inventory.")
    inv_parser.add_argument("--source-id", default="", help="Evidence provenance source ID.")
    inv_parser.add_argument("-o", "--output", help="Output file path for API inventory JSON.")
    inv_parser.add_argument("--json", action="store_true", help="Emit raw JSON to stdout.")

    # 2. replay subcommand
    replay_parser = subparsers.add_parser(
        "replay",
        help="Replay API requests bounded by destination allowlists and operational budgets.",
    )
    replay_parser.add_argument("-i", "--inventory", required=True, help="Path to API inventory JSON file.")
    replay_parser.add_argument(
        "--allow-destination",
        action="append",
        default=[],
        help="Allowed target host/pattern (repeatable or comma-separated).",
    )
    replay_parser.add_argument("--max-requests", type=int, default=50, help="Maximum requests budget (default: 50).")
    replay_parser.add_argument(
        "--rate-limit", type=float, default=10.0, help="Requests per second limit (default: 10.0)."
    )
    replay_parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5.0).")
    replay_parser.add_argument("--max-redirects", type=int, default=3, help="Maximum redirect hops (default: 3).")
    replay_parser.add_argument("--max-frames", type=int, default=10, help="Maximum WebSocket frames (default: 10).")
    replay_parser.add_argument(
        "--mode",
        choices=["offline", "live"],
        default="offline",
        help="Replayer mode: offline simulation; live requires the approved Python entry point.",
    )
    replay_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview exact requests, limits, evidence, and effects without dispatching work.",
    )
    replay_parser.add_argument(
        "--explain",
        action="store_true",
        help="Explain the side-effect-free replay preview without dispatching work.",
    )
    replay_parser.add_argument("-o", "--output", help="Output file path for replay report JSON.")
    replay_parser.add_argument("--json", action="store_true", help="Emit raw JSON to stdout.")

    # 3. inspect subcommand
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect an API inventory or replay session report file.",
    )
    inspect_parser.add_argument("file", help="Path to API inventory or replay report JSON file.")
    inspect_parser.add_argument("--json", action="store_true", help="Emit raw JSON to stdout.")

    return parser


def command_web_api(args: argparse.Namespace, *, root: Path | None = None) -> int:
    """Execute web-api subcommands."""
    cmd = getattr(args, "web_api_command", None)

    try:
        if cmd == "inventory":
            inventories: list[ApiInventory] = []

            if args.har:
                inventories.append(import_har(Path(args.har), source_id=args.source_id or None))
            if args.openapi:
                inventories.append(import_openapi(Path(args.openapi), source_id=args.source_id or None))
            if args.postman:
                inventories.append(import_postman(Path(args.postman), source_id=args.source_id or None))
            if args.raw:
                inventories.append(import_raw_http(Path(args.raw), source_id=args.source_id or None))

            if not inventories:
                print(
                    "error: at least one input source (--har, --openapi, --postman, --raw) is required", file=sys.stderr
                )
                return 1

            # Merge if multiple
            if len(inventories) == 1:
                inventory = inventories[0]
                if args.name:
                    inventory.name = args.name
            else:
                combined_name = args.name or f"Combined API Inventory ({len(inventories)} sources)"
                all_endpoints = []
                all_hosts = set()
                all_roles = []
                all_sessions = []
                all_unsupported = []
                all_sources = []
                for inv in inventories:
                    all_endpoints.extend(inv.endpoints)
                    all_hosts.update(inv.target_hosts)
                    all_roles.extend(inv.roles)
                    all_sessions.extend(inv.sessions)
                    all_unsupported.extend(inv.unsupported_features)
                    all_sources.extend(inv.imported_sources)

                inventory = ApiInventory(
                    inventory_id=f"inv-merged-{len(all_endpoints)}",
                    name=combined_name,
                    target_hosts=sorted(all_hosts),
                    endpoints=all_endpoints,
                    roles=all_roles,
                    sessions=all_sessions,
                    unsupported_features=all_unsupported,
                    imported_sources=sorted(set(all_sources)),
                    credentials_redacted=True,
                )

            if args.output:
                inventory.save(args.output)

            if args.json:
                print(json.dumps(inventory.to_dict(), indent=2))
                return 0

            print(f"=== Web Application & API Inventory: {inventory.name} ===")
            print(f"Inventory ID:        {inventory.inventory_id}")
            print(f"Target Hosts:        {', '.join(inventory.target_hosts) or 'None'}")
            print(f"Total Endpoints:     {len(inventory.endpoints)}")
            print(f"Roles Defined:       {len(inventory.roles)}")
            print(f"Sessions Isolated:   {len(inventory.sessions)}")
            print(f"Unsupported Features:{len(inventory.unsupported_features)}")
            print(f"Credentials Redacted:{inventory.credentials_redacted}")
            print()
            print("Endpoints Summary:")
            for ep in inventory.endpoints[:20]:
                auth_str = f" [Auth: {ep.auth_mechanisms[0].auth_type}]" if ep.auth_mechanisms else ""
                print(f"  {ep.method:<7} {ep.protocol:<9} {ep.path:<35}{auth_str}")
            if len(inventory.endpoints) > 20:
                print(f"  ... and {len(inventory.endpoints) - 20} more endpoints")

            if args.output:
                print(f"\nInventory saved to {args.output}")
            return 0

        elif cmd == "replay":
            inv_path = Path(args.inventory)
            if not inv_path.exists():
                print(f"error: inventory file not found: {inv_path}", file=sys.stderr)
                return 1

            inventory = ApiInventory.load(inv_path)

            # Parse destinations
            destinations: list[str] = []
            for item in args.allow_destination:
                for d in item.split(","):
                    d_clean = d.strip()
                    if d_clean:
                        destinations.append(d_clean)

            if not destinations:
                # Default to target hosts from inventory
                destinations = list(inventory.target_hosts)

            if not destinations:
                print("error: at least one --allow-destination must be specified", file=sys.stderr)
                return 1

            budget = ReplayBudget(
                max_requests=args.max_requests,
                rate_limit_rps=args.rate_limit,
                timeout_seconds=args.timeout,
                max_redirect_hops=args.max_redirects,
                max_websocket_frames=args.max_frames,
            )

            # Generate requests from endpoints
            requests: list[ReplayRequest] = []
            for i, ep in enumerate(inventory.endpoints):
                host = ep.host or (inventory.target_hosts[0] if inventory.target_hosts else "localhost")
                scheme = "wss" if ep.protocol == ApiProtocol.WEBSOCKET.value else "https"
                url = f"{scheme}://{host}{ep.path}"
                headers: dict[str, str] = {}
                for am in ep.auth_mechanisms:
                    if am.location == "header" and am.token_name:
                        headers[am.token_name] = f"Bearer [REDACTED:{am.credential_hash[:12]}]"

                requests.append(
                    ReplayRequest(
                        request_id=f"req-{i + 1:03d}",
                        endpoint_id=ep.endpoint_id,
                        method=ep.method,
                        url=url,
                        headers=headers,
                        query_parameters=dict(ep.query_parameters),
                        protocol=ep.protocol,
                    )
                )

            if getattr(args, "dry_run", False) or getattr(args, "explain", False):
                preview = _replay_preview_document(
                    inventory=inventory,
                    requests=requests,
                    destinations=destinations,
                    budget=budget,
                    requested_mode=args.mode,
                )
                if args.json:
                    print(json.dumps(preview, indent=2))
                else:
                    _print_replay_preview(preview)
                return 0

            if args.mode == "live":
                print(
                    "error: live replay requires the approved Python entry point "
                    "execute_authorized_replay_session with ActionPlan, approval, "
                    "worker-readiness, and scope controls",
                    file=sys.stderr,
                )
                return 2

            report = execute_replay_session(
                requests=requests,
                allowed_destinations=destinations,
                budget=budget,
                replayer=OfflineSyntheticReplayer(),
            )

            if args.output:
                report.save(args.output)

            if args.json:
                print(json.dumps(report.to_dict(), indent=2))
                return 0

            print(f"=== Web API Request Replay Report: {report.session_id} ===")
            print(f"Target Hosts:           {', '.join(report.target_hosts)}")
            print(f"Allowed Destinations:   {', '.join(report.allowed_destinations)}")
            print(f"Budget Max Requests:    {report.budget.max_requests}")
            print(f"Dispatched Requests:    {report.total_dispatched}")
            print(f"Successful Replays:     {report.total_successful}")
            print(f"Failed Replays:         {report.total_failed}")
            print(f"Destination Violations: {report.destination_violations}")
            print()
            print("Responses:")
            for resp in report.responses[:15]:
                status_icon = "✓" if resp.replay_success else "✗"
                err = f" ({resp.error_message})" if resp.error_message else ""
                print(
                    f"  [{status_icon}] {resp.request_id} -> Status {resp.status_code} ({resp.latency_ms:.1f}ms){err}"
                )
            if len(report.responses) > 15:
                print(f"  ... and {len(report.responses) - 15} more responses")

            if args.output:
                print(f"\nReplay report saved to {args.output}")
            return 0

        elif cmd == "inspect":
            target_path = Path(args.file)
            if not target_path.exists():
                print(f"error: file not found: {target_path}", file=sys.stderr)
                return 1

            data = json.loads(target_path.read_text(encoding="utf-8"))

            if args.json:
                print(json.dumps(data, indent=2))
                return 0

            if "endpoints" in data:
                # ApiInventory
                inv = ApiInventory.from_dict(data)
                print(f"=== API Inventory: {inv.name} ({inv.inventory_id}) ===")
                print(f"Target Hosts:        {', '.join(inv.target_hosts)}")
                print(f"Total Endpoints:     {len(inv.endpoints)}")
                print(f"Roles Defined:       {len(inv.roles)}")
                print(f"Sessions Isolated:   {len(inv.sessions)}")
                print(f"Unsupported Features:{len(inv.unsupported_features)}")
                print(f"Credentials Redacted:{inv.credentials_redacted}")
                print()
                print("Endpoints:")
                for ep in inv.endpoints:
                    auths = [a.auth_type for a in ep.auth_mechanisms] or ["none"]
                    print(f"  {ep.method:<6} {ep.protocol:<9} {ep.path:<30} Auth: {','.join(auths)}")
                if inv.unsupported_features:
                    print("\nUnsupported Protocol Features:")
                    for uf in inv.unsupported_features:
                        print(f"  ! [{uf.protocol}] {uf.feature_name}: {uf.reason}")
                return 0

            elif "budget" in data and "responses" in data:
                # ReplaySessionReport
                rep = ReplaySessionReport.from_dict(data)
                print(f"=== Replay Session Report: {rep.session_id} ===")
                print(f"Target Hosts:           {', '.join(rep.target_hosts)}")
                print(f"Allowed Destinations:   {', '.join(rep.allowed_destinations)}")
                print(f"Total Dispatched:       {rep.total_dispatched}")
                print(f"Successful:             {rep.total_successful}")
                print(f"Failed:                 {rep.total_failed}")
                print(f"Destination Violations: {rep.destination_violations}")
                print()
                for resp in rep.responses:
                    status_icon = "✓" if resp.replay_success else "✗"
                    err = f" ({resp.error_message})" if resp.error_message else ""
                    print(f"  [{status_icon}] {resp.request_id}: {resp.status_code} ({resp.latency_ms:.1f}ms){err}")
                return 0
            else:
                print(f"Unrecognized file schema: {target_path}", file=sys.stderr)
                return 1

    except Exception as err:
        print(f"web-api error: {err}", file=sys.stderr)
        return 1

    return 0
