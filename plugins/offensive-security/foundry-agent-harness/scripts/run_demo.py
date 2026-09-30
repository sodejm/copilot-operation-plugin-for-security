#!/usr/bin/env python3
"""Deterministic demo runner for Foundry Agent Harness."""

from __future__ import annotations

import sys
from pathlib import Path

# Add plugin root to sys.path so foundryharness can be imported cleanly
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from foundryharness.cli import load_scenarios
from foundryharness.gate import IndependentAuthorizationGate
from foundryharness.mock_sandbox import MockSandbox
from foundryharness.reporting import render_markdown_report
from foundryharness.simulator import evaluate_scenario


def main() -> int:
    scenarios_dir = PLUGIN_ROOT / "scenarios"
    if not scenarios_dir.is_dir():
        print(f"Error: Scenarios directory not found at {scenarios_dir}", file=sys.stderr)
        return 1

    print("=== Microsoft Foundry Adversarial Agent Review Demo ===")
    print(f"Loading evaluation scenarios from: {scenarios_dir.relative_to(REPO_ROOT)}")

    scenarios = load_scenarios(None, scenarios_dir)
    sandbox = MockSandbox()
    gate = IndependentAuthorizationGate()

    events = []
    for sc in scenarios:
        event = evaluate_scenario(sc, sandbox, gate)
        events.append(event)

    target_agent = {
        "agent_name": "Contoso-Enterprise-Foundry-Agent",
        "agent_version": "1.0.0",
        "framework": "Microsoft Foundry / Semantic Kernel",
    }
    environment = "mock-sandbox-offline"

    report_md = render_markdown_report(scenarios, events, target_agent, environment)
    print("\n" + report_md)

    denied = sum(1 for e in events if e.outcome_level == "denied_tool_call")
    print(
        f"\n[OK] Evaluated {len(events)} adversarial scenarios. "
        f"Independent authorization gate successfully intercepted and blocked {denied} unauthorized tool calls."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
