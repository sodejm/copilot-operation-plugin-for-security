"""Operator command-line interface for the Foundry Agent Harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    source_root = Path(__file__).resolve().parents[4]
    if (source_root / "cops" / "__init__.py").is_file():
        sys.path.insert(0, str(source_root))
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from foundryharness.auth_laboratory import load_auth_cases
    from foundryharness.bounded_json import JSONInputError, decode_json, read_regular_file
    from foundryharness.gate import IndependentAuthorizationGate
    from foundryharness.laboratory import LabError, load_lab_cases, run_lab_case
    from foundryharness.mock_sandbox import MockSandbox
    from foundryharness.models import HarnessError, Scenario
    from foundryharness.reporting import render_json_report, render_markdown_report
    from foundryharness.simulator import evaluate_scenario
else:
    from .auth_laboratory import load_auth_cases
    from .bounded_json import JSONInputError, decode_json, read_regular_file
    from .gate import IndependentAuthorizationGate
    from .laboratory import LabError, load_lab_cases, run_lab_case
    from .mock_sandbox import MockSandbox
    from .models import HarnessError, Scenario
    from .reporting import render_json_report, render_markdown_report
    from .simulator import evaluate_scenario

def load_scenarios(scenario_path: Path | None, scenarios_dir: Path | None) -> list[Scenario]:
    """Load scenarios from a single file or a directory."""
    scenarios: list[Scenario] = []

    if scenario_path:
        if not scenario_path.is_file():
            raise HarnessError(f"Scenario file not found: {scenario_path}")
        data = json.loads(scenario_path.read_text(encoding="utf-8"))
        scenarios.append(Scenario.from_dict(data))
    elif scenarios_dir:
        if not scenarios_dir.is_dir():
            raise HarnessError(f"Scenarios directory not found: {scenarios_dir}")
        for p in sorted(scenarios_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if "scenario_id" in data:
                    scenarios.append(Scenario.from_dict(data))
            except Exception as e:
                print(f"Warning: Skipping {p.name}: {e}", file=sys.stderr)
    else:
        raise HarnessError("Must specify either --scenario or --scenarios-dir")

    if not scenarios:
        raise HarnessError("No valid scenarios found.")
    return scenarios


def _load_json_object(path: Path, label: str) -> dict:
    try:
        value = decode_json(read_regular_file(path, max_bytes=1048576), max_bytes=1048576)
        if not isinstance(value, dict):
            raise JSONInputError("object_required")
        return value
    except JSONInputError:
        raise LabError(f"{label} must be a bounded regular file containing strict JSON") from None


def _emit(value: str, output: Path | None) -> None:
    if output is None:
        print(value, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(value, encoding="utf-8")
    print(f"Wrote report to {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="foundryharness",
        description="Offline synthetic agent authorization scenarios and local MCP fixtures.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run / evaluate command
    run_parser = subparsers.add_parser("evaluate", aliases=["run"], help="evaluate scenarios against mock sandbox")
    run_parser.add_argument("--scenario", type=Path, help="path to a single scenario JSON file")
    run_parser.add_argument("--scenarios-dir", type=Path, help="path to directory of scenario JSON files")
    run_parser.add_argument("--output", type=Path, help="write report output to file")
    run_parser.add_argument("--json", action="store_true", help="output structured JSON instead of Markdown")
    run_parser.add_argument("--agent-name", default="Synthetic-Scenario-Fixture", help="scenario report label")
    run_parser.add_argument("--agent-version", default="1.0.0", help="scenario report version label")

    # list command
    list_parser = subparsers.add_parser("list", help="list available scenario definitions")
    list_parser.add_argument("--scenarios-dir", type=Path, required=True, help="path to directory of scenarios")

    lab_parser = subparsers.add_parser("lab", help="run local synthetic agent and MCP fixture cases")
    lab_parser.add_argument(
        "--cases",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "lab_cases",
        help="lab case JSON file or directory",
    )
    lab_parser.add_argument("--output", type=Path, help="write report output to file")
    lab_parser.add_argument("--json", action="store_true", help="output structured JSON instead of a concise summary")

    plan_parser = subparsers.add_parser(
        "auth-plan",
        help="compile an immutable authorization laboratory ActionPlan for COPS signing",
    )
    plan_parser.add_argument(
        "--cases",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "auth_cases",
        help="authorization case JSON file or directory",
    )
    plan_parser.add_argument("--plan-id", required=True, help="COPS action-plan identifier")
    plan_parser.add_argument("--engagement-id", required=True, help="COPS engagement identifier")
    plan_parser.add_argument("--created-at", required=True, help="ActionPlan creation timestamp")
    plan_parser.add_argument("--output", type=Path, help="write ActionPlan JSON to file")

    auth_parser = subparsers.add_parser("auth-lab", help="run local synthetic MCP authorization cases")
    auth_parser.add_argument(
        "--cases",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "auth_cases",
        help="authorization case JSON file or directory",
    )
    auth_parser.add_argument("--plan", type=Path, required=True, help="signed lifecycle ActionPlan JSON")
    auth_parser.add_argument("--engagement", type=Path, required=True, help="COPS engagement JSON")
    auth_parser.add_argument("--authorization", type=Path, required=True, help="signed execution authorization JSON")
    auth_parser.add_argument("--trust-store", type=Path, required=True, help="private verifier trust-store JSON")
    auth_parser.add_argument("--worker-identity", required=True, help="worker identity bound by the authorization")
    auth_parser.add_argument("--approval-store", type=Path, required=True, help="private COPS ApprovalStore database")
    auth_parser.add_argument("--json", action="store_true", help="output structured JSON instead of a concise summary")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command in ("auth-plan", "auth-lab"):
            try:
                from cops.contracts.models import ActionPlan
                from cops.execution.authorization import AuthorizationTrustStore
                from cops.execution.store import ApprovalStore
                from foundryharness.auth_approval import build_auth_plan, run_auth_cases
            except ModuleNotFoundError as exc:
                if exc.name == "cops":
                    raise LabError("auth-plan and auth-lab require the COPS source runtime") from None
                raise
        if args.command in ("evaluate", "run"):
            scenarios = load_scenarios(args.scenario, args.scenarios_dir)
            sandbox = MockSandbox()
            gate = IndependentAuthorizationGate()

            events = []
            for sc in scenarios:
                event = evaluate_scenario(sc, sandbox, gate)
                events.append(event)

            target_agent = {
                "agent_name": args.agent_name,
                "agent_version": args.agent_version,
                "framework": "Deterministic scenario simulator",
            }
            environment = "mock-sandbox-offline"

            if args.json:
                data = render_json_report(scenarios, events, target_agent, environment)
                out_str = json.dumps(data, indent=2) + "\n"
            else:
                out_str = render_markdown_report(scenarios, events, target_agent, environment) + "\n"

            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(out_str, encoding="utf-8")
                print(f"Wrote report to {args.output}")
            else:
                print(out_str, end="")
            return 0

        elif args.command == "list":
            scenarios = load_scenarios(None, args.scenarios_dir)
            print(f"Discovered {len(scenarios)} scenarios in {args.scenarios_dir}:\n")
            print(f"{'ID':<15} {'Surface':<25} {'Title'}")
            print("-" * 75)
            for sc in scenarios:
                print(f"{sc.scenario_id:<15} {sc.attacker_controlled_surface:<25} {sc.title}")
            return 0

        elif args.command == "lab":
            cases = load_lab_cases(args.cases)
            results = [run_lab_case(case) for case in cases]
            passed = all(result["expectation_met"] for result in results)
            if args.json:
                out_str = (
                    json.dumps(
                        {
                            "schema_version": "cops.agent-mcp-lab-run/v1",
                            "environment": "local-synthetic-fixtures",
                            "all_expectations_met": passed,
                            "results": results,
                        },
                        indent=2,
                    )
                    + "\n"
                )
            else:
                lines = [
                    "Local synthetic agent and MCP fixture laboratory",
                    f"Cases: {len(results)}; expectations met: {sum(result['expectation_met'] for result in results)}",
                ]
                for result in results:
                    lines.append(
                        f"{result['case_id']}: denied={len(result['denied_calls'])} "
                        f"effects={len(result['executed_effects'])} "
                        f"cleanup={result['cleanup_verified']} "
                        f"expectation_met={result['expectation_met']}"
                    )
                out_str = "\n".join(lines) + "\n"
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(out_str, encoding="utf-8")
                print(f"Wrote report to {args.output}")
            else:
                print(out_str, end="")
            return 0 if passed else 1

        elif args.command == "auth-plan":
            plan = build_auth_plan(
                load_auth_cases(args.cases),
                plan_id=args.plan_id,
                engagement_id=args.engagement_id,
                created_at=args.created_at,
            )
            _emit(json.dumps(plan.to_dict(), indent=2) + "\n", args.output)
            return 0

        elif args.command == "auth-lab":
            cases = load_auth_cases(args.cases)
            plan = ActionPlan.from_dict(_load_json_object(args.plan, "ActionPlan"))
            engagement = _load_json_object(args.engagement, "engagement")
            authorization = _load_json_object(args.authorization, "execution authorization")
            trust_store = AuthorizationTrustStore.from_file(args.trust_store)
            approval_store = ApprovalStore(args.approval_store, require_secure_perms=True)
            report = run_auth_cases(
                cases,
                plan=plan,
                authorization=authorization,
                engagement=engagement,
                trust_store=trust_store,
                worker_identity=args.worker_identity,
                approval_store=approval_store,
            )
            results = report["results"]
            passed = report["security_pass"]
            if args.json:
                out_str = json.dumps(report, indent=2) + "\n"
            else:
                lines = [
                    "Local synthetic MCP authorization laboratory",
                    f"Cases: {len(results)}/{report['planned_case_count']}; "
                    f"expectations met: {sum(result['expectation_met'] for result in results)}; "
                    f"cancelled: {report['cancelled']}",
                ]
                for result in results:
                    lines.append(
                        f"{result['case_id']}: outcome={result['outcome']} "
                        f"effects={len(result['observed_effects'])} "
                        f"process_exit={result['cleanup']['process_exit_observed']} "
                        f"directory_removed={result['cleanup']['private_directory_removed']} "
                        f"expectation_met={result['expectation_met']}"
                    )
                out_str = "\n".join(lines) + "\n"
            _emit(out_str, None)
            return 0 if passed else 1

    except (HarnessError, LabError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"foundryharness error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
