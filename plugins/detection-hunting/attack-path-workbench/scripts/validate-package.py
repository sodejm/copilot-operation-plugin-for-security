"""Run the package's offline tests and a repeatable CLI smoke test."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


PACKAGE = Path(__file__).resolve().parents[1]
CLI = PACKAGE / "scripts/attackpath.py"
FIXTURE = PACKAGE / "fixtures/illustrative/input.json"


def run(*args: str, cwd: Path = PACKAGE) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, *args], cwd=cwd, capture_output=True, text=True, timeout=90
    )
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr or result.stdout}")
    return result


def main() -> int:
    run("-m", "unittest", "discover", "-s", "tests", "-v")
    with tempfile.TemporaryDirectory(prefix="attackpath-check-") as directory:
        outputs = []
        for number in (1, 2):
            output = Path(directory) / f"run-{number}"
            run(str(CLI), "analyze", str(FIXTURE), "--output-dir", str(output))
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            assert len(report["supported_paths"]) == 1
            assert len(report["candidate_paths"]) == 1
            assert report["supported_paths"][0]["impact"]["business_rating"] == "unrated"
            outputs.append((output / "report.json").read_bytes())
        assert outputs[0] == outputs[1], "identical inputs produced different reports"
    intent = json.loads(run(str(CLI), "query-intent", "--start", "ILL-FINDING",
                            "--target", "ILL-CROWN", "--scope", "ILL-SCOPE").stdout)
    assert intent["render_status"] == "blocked_pending_docs"
    print(json.dumps({"status": "passed", "unit_tests": "passed", "reproducible": True,
                      "wiz_query_rendering": "blocked_pending_docs"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
