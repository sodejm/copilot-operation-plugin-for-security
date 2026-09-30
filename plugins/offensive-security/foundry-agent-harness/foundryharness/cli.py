"""Operator command-line interface for the Foundry Agent Harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from foundryharness.gate import IndependentAuthorizationGate
    from foundryharness.mock_sandbox import MockSandbox
    from foundryharness.models import HarnessError, Scenario
    from foundryharness.reporting import render_json_report, render_markdown_report
    from foundryharness.simulator import evaluate_scenario
else:
    from .gate import IndependentAuthorizationGate
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="foundryharness",
        description="Offline adversarial agent review harness for Microsoft Foundry agents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run / evaluate command
    run_parser = subparsers.add_parser("evaluate", aliases=["run"], help="evaluate scenarios against mock sandbox")
    run_parser.add_argument("--scenario", type=Path, help="path to a single scenario JSON file")
    run_parser.add_argument("--scenarios-dir", type=Path, help="path to directory of scenario JSON files")
    run_parser.add_argument("--output", type=Path, help="write report output to file")
    run_parser.add_argument("--json", action="store_true", help="output structured JSON instead of Markdown")
    run_parser.add_argument("--agent-name", default="Foundry-Ops-Support-Agent", help="target agent name")
    run_parser.add_argument("--agent-version", default="1.0.0", help="target agent version")

    # list command
    list_parser = subparsers.add_parser("list", help="list available scenario definitions")
    list_parser.add_argument("--scenarios-dir", type=Path, required=True, help="path to directory of scenarios")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
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
                "framework": "Microsoft Foundry / Semantic Kernel",
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

    except HarnessError as exc:
        print(f"foundryharness error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
