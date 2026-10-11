"""Command line interface for laboratory harness operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cops.contracts.models import LaboratoryEnvironment

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
            raise ValueError(
                "laboratory verification requires an operator-owned observation provider "
                "and a verified SSH endpoint inventory; use the Python harness API"
            )

        elif cmd == "reset":
            raise ValueError(
                "laboratory reset requires an operator-owned observation provider, "
                "a challenged worker reset receipt, and a verified SSH endpoint inventory; "
                "use the Python harness API"
            )

        elif cmd == "matrix":
            output_data = {
                "supported_os": harness.matrix.supported_os,
                "supported_distributions": harness.matrix.supported_distributions,
                "supported_architectures": harness.matrix.supported_architectures,
                "supported_runtimes": harness.matrix.supported_runtimes,
                "tool_minimum_versions": harness.matrix.tool_minimum_versions,
            }

        elif cmd == "run":
            raise ValueError(
                "laboratory execution requires live observations, verified worker inventories, "
                "and an explicit scope guard; use the Python harness API"
            )

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
