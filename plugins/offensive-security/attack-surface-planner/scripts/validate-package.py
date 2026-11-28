"""Run the package's offline regression suite and reproducibility gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
CLI = PACKAGE / "scripts/plan.py"
FIXTURE = PACKAGE / "fixtures/synthetic/scope.json"


def main() -> int:
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                            cwd=PACKAGE, check=False, timeout=90)
    if result.returncode:
        return result.returncode
    outputs = []
    for _ in range(2):
        result = subprocess.run([sys.executable, str(CLI), str(FIXTURE)], cwd=PACKAGE,
                                capture_output=True, text=True, check=True, timeout=30)
        report = json.loads(result.stdout)
        assert report["mode"] == "offline" and report["network_requests"] == 0
        assert report["summary"] == {"in_scope": 4, "excluded": 3, "unresolved": 1}
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1], "identical inputs produced different plans"
    print(json.dumps({"status": "passed", "reproducible": True, "network_requests": 0},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
