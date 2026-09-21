#!/usr/bin/env python3
"""Run COPS repository, plugin, scenario, and contributor-skill checks."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

from repository_files import repository_files


ROOT = Path(__file__).resolve().parents[2]


def run(command: list[str]) -> bool:
    print("+ " + " ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, check=False)
    return result.returncode == 0


def validate_python(root: Path = ROOT) -> bool:
    ok = True
    for path in repository_files(root):
        if path.suffix != ".py":
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as error:
            print(f"error: {error}", file=sys.stderr)
            ok = False
    if ok:
        print("Python sources parse successfully.")
    return ok


def main() -> int:
    checks = [
        validate_python(),
        run([sys.executable, "scripts/agent/validate_contract.py"]),
        run([sys.executable, "scripts/agent/sync_adapters.py", "--check"]),
        run([sys.executable, "scripts/agent/validate_marketplace.py"]),
        run([sys.executable, "-m", "cops", "generate", "--check"]),
        run([sys.executable, "-m", "cops", "check"]),
    ]
    if (ROOT / "tests").is_dir():
        checks.append(run([sys.executable, "-m", "pytest", "tests", "-q"]))
    for suite in sorted((ROOT / ".agents" / "skills").glob("*/tests")):
        checks.append(run([sys.executable, "-m", "unittest", "discover", "-s", str(suite), "-v"]))
    if (ROOT / ".git").exists():
        checks.append(run(["git", "diff", "--check"]))
    if all(checks):
        print("All COPS checks passed.")
        return 0
    print("One or more COPS checks failed.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
