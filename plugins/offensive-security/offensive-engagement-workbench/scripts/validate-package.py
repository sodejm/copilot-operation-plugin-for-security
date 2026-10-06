#!/usr/bin/env python3
"""Run the package offline regression suite and reproducibility gate."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE))

DEMO = PACKAGE / "scripts" / "demo.py"


def main() -> int:
    suite = unittest.defaultTestLoader.discover(str(PACKAGE / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        return 1

    outputs = []
    env = dict(sys.modules.get("os", __import__("os")).environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}:{PACKAGE}:{env.get('PYTHONPATH', '')}"

    for _ in range(2):
        res = subprocess.run(
            [sys.executable, str(DEMO)],
            cwd=PACKAGE,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            env=env,
        )
        report = json.loads(res.stdout)
        assert report["status"] == "passed"
        assert report["network_requests"] == 0
        assert report["operations_count"] >= 1
        outputs.append(res.stdout)

    assert outputs[0] == outputs[1], "identical inputs produced different plans"
    print(json.dumps({"status": "passed", "reproducible": True, "network_requests": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
