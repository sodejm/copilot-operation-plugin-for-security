"""Semantic and optimized-mode checks for the documented host playback."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DEMO = PACKAGE / "scripts/demo.py"


class PlaybackTests(unittest.TestCase):
    def test_demo_reports_each_semantic_case_repeatably(self):
        outputs = []
        for _ in range(2):
            result = subprocess.run(
                [sys.executable, str(DEMO)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["mode"], "offline_import")
            self.assertEqual(
                set(report["cases"]),
                {
                    "positive",
                    "negative",
                    "fixed",
                    "windows_vulnerable",
                    "windows_protected",
                    "windows_remediated",
                    "windows_unsupported",
                    "unknown_context",
                    "unverified_cleanup",
                },
            )
            self.assertEqual(report["cases"]["positive"]["counts"]["reported_canary_crossing"], 1)
            self.assertEqual(report["cases"]["negative"]["counts"]["reported_canary_blocked"], 1)
            self.assertEqual(report["cases"]["fixed"]["counts"]["reported_canary_blocked"], 1)
            self.assertEqual(
                report["cases"]["windows_vulnerable"]["counts"]["reported_canary_crossing"],
                1,
            )
            self.assertEqual(
                report["cases"]["windows_protected"]["counts"]["reported_canary_blocked"],
                1,
            )
            self.assertEqual(
                report["cases"]["windows_remediated"]["counts"]["reported_canary_blocked"],
                1,
            )
            self.assertEqual(sum(report["cases"]["windows_unsupported"]["counts"].values()), 0)
            self.assertEqual(report["cases"]["unknown_context"]["counts"]["reported_canary_crossing"], 0)
            self.assertTrue(report["cases"]["unverified_cleanup"]["rejected"])
            outputs.append(report)
        self.assertEqual(outputs[0], outputs[1])

    def test_optimized_mode_keeps_semantic_checks_enabled(self):
        bad_report = {
            "mode": "offline_import",
            "source": {"kind": "synthetic_lab"},
            "observations": [{"classification": "wrong", "cleanup_reported": True}],
            "counts": {"reported_canary_crossing": 1, "reported_canary_blocked": 1},
            "coverage": [{}] * 8,
        }
        code = (
            "import importlib.util\n"
            f"spec = importlib.util.spec_from_file_location('host_demo', {str(DEMO)!r})\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            f"module.import_case = lambda source: {bad_report!r}\n"
            "module.main()\n"
        )
        result = subprocess.run(
            [sys.executable, "-O", "-c", code],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("classification changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
