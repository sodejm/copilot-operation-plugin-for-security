from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


class ThreatIntelligencePlaybackTests(unittest.TestCase):
    def test_demo_exercises_paths_under_optimized_python(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-O", str(PACKAGE_ROOT / "scripts" / "run_demo.py")],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        result = json.loads(completed.stdout)

        self.assertEqual(result["network_mode"], "injected-mock-only")
        self.assertIs(result["live_integrations_validated"], False)
        self.assertEqual(result["misp"]["initial"]["status"], "positive")
        self.assertTrue(result["misp"]["initial"]["conflicts"])
        self.assertEqual(result["misp"]["fresh_cache"]["cache"], "fresh")
        self.assertEqual(result["misp"]["stale_cache"]["cache"], "stale")
        self.assertEqual(result["misp"]["as_of_replay"]["cache"], "fresh")
        self.assertEqual(result["taxii_partial"]["status"], "partial")
        self.assertEqual(result["taxii_partial"]["error"], "pagination_limit")
        self.assertEqual(result["microsoft_failure"]["status"], "error")
        self.assertEqual(result["microsoft_failure"]["error"], "http_503")
