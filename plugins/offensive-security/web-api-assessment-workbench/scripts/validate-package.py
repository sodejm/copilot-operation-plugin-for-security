#!/usr/bin/env python3
"""Offline package gate validator for Web API Assessment Workbench."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent


def validate() -> int:
    # 1. Check manifests and schemas
    manifests = [
        PLUGIN_ROOT / "package.json",
        PLUGIN_ROOT / "plugin.json",
        PLUGIN_ROOT / ".claude-plugin" / "plugin.json",
        PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
        PLUGIN_ROOT / "org.cops" / "prerequisites.json",
    ]
    for m in manifests:
        if not m.is_file():
            print(f"FAIL: Missing manifest {m.relative_to(REPO_ROOT)}", file=sys.stderr)
            return 1
        try:
            json.loads(m.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"FAIL: Malformed JSON in {m}: {e}", file=sys.stderr)
            return 1

    # 2. Run only standard-library offline tests. Real-service pytest cases are
    # required separately by the repository acceptance gate, never imported here.
    test_res = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_workbench*.py", "-v"],
        cwd=PLUGIN_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if test_res.returncode != 0:
        print(f"FAIL: Unit tests failed:\n{test_res.stderr}\n{test_res.stdout}", file=sys.stderr)
        return test_res.returncode

    # 3. Check demo reproducibility
    demo_script = PLUGIN_ROOT / "scripts" / "demo.py"
    outputs = []
    for _ in range(2):
        res = subprocess.run(
            [sys.executable, str(demo_script)],
            cwd=PLUGIN_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(res.stdout)
        if data.get("network_requests") != 0:
            print("FAIL: Demo made network requests!", file=sys.stderr)
            return 1
        outputs.append(res.stdout)

    if outputs[0] != outputs[1]:
        print("FAIL: Demo output is not deterministic/reproducible", file=sys.stderr)
        return 1

    print(json.dumps({"network_requests": 0, "reproducible": True, "status": "passed"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(validate())
