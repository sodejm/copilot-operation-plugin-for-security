from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


class IncidentResponsePlaybackTests(unittest.TestCase):
    def test_demo_exercises_paths_under_optimized_python(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-O", str(PACKAGE_ROOT / "scripts" / "run_demo.py")],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        result = json.loads(completed.stdout)

        self.assertEqual(result["execution_boundary"]["network_calls"], 0)
        self.assertIs(result["execution_boundary"]["temporary_artifacts_removed"], True)
        self.assertEqual(result["primary"]["dry_run_decision"], "ready")
        self.assertIs(result["primary"]["dry_run_state_unchanged"], True)
        self.assertEqual(result["primary"]["execute_status"], "applied")
        self.assertEqual(result["primary"]["verification_state"], "isolated")
        self.assertIs(result["replay_rejection"]["rejected"], True)
        self.assertIn("duplicate or replayed", result["replay_rejection"]["reason"])
        self.assertIs(result["expiry_rejection"]["rejected"], True)
        self.assertIn("expired", result["expiry_rejection"]["reason"])
        self.assertEqual(result["rollback"]["execute_status"], "partial-rolled-back")
        self.assertEqual(result["rollback"]["verification_state"], "active")
