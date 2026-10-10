"""Command line interface for laboratory harness operations."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

from cops.contracts.models import ActionPlan, Engagement, LaboratoryEnvironment
from cops.execution.authorization import AuthorizationTrustStore
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.execution.store import ApprovalStore
from cops.execution.worker import WorkerCapabilityInventory

from .harness import LaboratoryHarness

ROOT = Path(__file__).resolve().parents[2]


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


def command_laboratory(args: argparse.Namespace, root: Path = ROOT) -> int:
    """Handle `cops lab <register|verify|reset|matrix|run>`."""
    cmd = getattr(args, "lab_command", None)
    harness = LaboratoryHarness()

    try:
        if cmd == "register":
            doc = _load_json_or_file(args.environment)
            env = harness.register_environment(doc)
            output_data = env.to_dict()

        elif cmd == "verify":
            doc = _load_json_or_file(args.environment)
            env = LaboratoryEnvironment.from_dict(doc)
            req_tools = None
            if getattr(args, "tools", None):
                req_tools = [t.strip() for t in args.tools.split(",") if t.strip()]
            env = harness.verify_environment(env, required_tools=req_tools, mock_checks=getattr(args, "mock", True))
            output_data = env.to_dict()

        elif cmd == "reset":
            doc = _load_json_or_file(args.environment)
            env = LaboratoryEnvironment.from_dict(doc)
            env = harness.reproducible_reset(env, mock_reset=getattr(args, "mock", True))
            output_data = env.to_dict()

        elif cmd == "matrix":
            output_data = {
                "supported_os": harness.matrix.supported_os,
                "supported_distributions": harness.matrix.supported_distributions,
                "supported_architectures": harness.matrix.supported_architectures,
                "supported_runtimes": harness.matrix.supported_runtimes,
                "tool_minimum_versions": harness.matrix.tool_minimum_versions,
            }

        elif cmd == "run":
            env_doc = _load_json_or_file(args.environment)
            plan_doc = _load_json_or_file(args.plan)
            auth_doc = _load_json_or_file(args.authorization)
            env = LaboratoryEnvironment.from_dict(env_doc)
            plan = ActionPlan.from_dict(plan_doc)
            engagement = Engagement.from_dict(_load_json_or_file(args.engagement))
            trust_store = AuthorizationTrustStore.from_file(args.authorization_trust_store)
            worker_inventory = WorkerCapabilityInventory.from_file(
                args.worker_inventory,
                expected_worker_identity=getattr(args, "worker_id", None) or env.owner,
            )

            case_type = getattr(args, "case_type", "positive")
            store = ApprovalStore(Path(args.store)) if getattr(args, "store", None) else None

            scope_definition = ScopeDefinition.from_engagement_scope(engagement.scope)
            if getattr(args, "allowed_cidr", None):
                from cops.execution.scope_guard import parse_ip_or_network

                net = parse_ip_or_network(args.allowed_cidr)
                if not isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    raise ValueError("--allowed-cidr must be an IPv4 or IPv6 network")
                if not any(
                    net.version == approved.version and net.subnet_of(approved)
                    for approved in scope_definition.included_networks
                ):
                    raise ValueError("--allowed-cidr must be contained within the engagement scope")
                if any(
                    net.version == excluded.version and net.overlaps(excluded)
                    for excluded in scope_definition.excluded_networks
                ) or any(address in net for address in scope_definition.excluded_ips):
                    raise ValueError("--allowed-cidr overlaps an engagement exclusion")
                # The override narrows the engagement's network scope. It must not retain
                # independently approved IP, domain, or cloud-resource destinations.
                scope_definition.included_networks = [net]
                scope_definition.included_ips.clear()
                scope_definition.included_domains.clear()
                scope_definition.included_cloud_resources.clear()
            guard = ScopeGuard(scope_definition)

            result = harness.execute_case(
                environment=env,
                action_plan=plan,
                authorization=auth_doc,
                case_type=case_type,
                trust_store=trust_store,
                engagement=engagement,
                worker_inventory=worker_inventory,
                store=store,
                scope_guard=guard,
            )
            output_data = result.to_dict()

        else:
            print(f"Unknown laboratory command: {cmd}", file=sys.stderr)
            return 2

        formatted = json.dumps(output_data, indent=2)
        if getattr(args, "output", None):
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(formatted, encoding="utf-8")
        else:
            print(formatted)
        return 0

    except Exception as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
