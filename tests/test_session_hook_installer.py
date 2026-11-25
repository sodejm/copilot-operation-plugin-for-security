"""Verify the entry point used by make setup-hooks."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.agent.check_issue_coverage import evaluate_coverage


class InstallerTests(unittest.TestCase):
    def test_forwards_revision_and_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "repo"
            wrapper = root / "scripts/agent/install_hooks.py"
            wrapper.parent.mkdir(parents=True)
            shutil.copyfile(Path(__file__).resolve().parents[1] / "scripts/agent/install_hooks.py", wrapper)
            gate = root / "tools/push_gate/gate.py"
            gate.parent.mkdir(parents=True)
            gate.write_text(
                "import json, sys\nfrom pathlib import Path\n"
                "Path('arguments.json').write_text(json.dumps(sys.argv[1:]))\n"
                "sys.exit(7)\n",
                encoding="utf-8",
            )
            result = subprocess.run([sys.executable, str(wrapper), "--revision", "HEAD"], cwd=directory, check=False)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(json.loads((root / "arguments.json").read_text()), ["install", "--revision", "HEAD"])

    def test_plan_only_coverage(self):
        """Planning can precede tests while mixed changes still require them."""
        plan = "docs/session-plans/new-output.json"
        for paths, expected in [([plan], True), ([plan, "app.py"], False), (["docs/guide.md"], False)]:
            with self.subTest(paths=paths):
                self.assertEqual(evaluate_coverage("codex/new-output", paths, []).passed, expected)
