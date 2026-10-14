#!/usr/bin/env python3
"""Run the package offline regression suite and reproducibility gate."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE))

DEMO = PACKAGE / "scripts" / "demo.py"
EXPECTED = {
    "engagement_id": "eng-synthetic-e03",
    "mode": "planning",
    "network_requests": 0,
    "operations_count": 1,
    "status": "passed",
    "target": "10.100.0.10",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    suite = unittest.defaultTestLoader.discover(str(PACKAGE / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        return 1

    outputs = []
    env = dict(sys.modules.get("os", __import__("os")).environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}:{PACKAGE}:{env.get('PYTHONPATH', '')}"

    with tempfile.TemporaryDirectory() as directory:
        output_dir = Path(directory)
        for _ in range(2):
            res = subprocess.run(
                [
                    sys.executable,
                    str(DEMO),
                    "--tool-version",
                    "python3=3.11.9",
                    "--output-dir",
                    str(output_dir),
                ],
                cwd=PACKAGE,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
                env=env,
            )
            report = json.loads(res.stdout)
            _require(report == EXPECTED, "demo summary failed semantic validation")
            outputs.append(res.stdout)

        _require(outputs[0] == outputs[1], "identical inputs produced different summaries")
        _require(
            json.loads((output_dir / "playback-result.json").read_text(encoding="utf-8")) == EXPECTED,
            "saved playback result differs from validated stdout",
        )
    print(json.dumps({"status": "passed", "reproducible": True, "network_requests": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
