"""Exercise the documented playback through the public import command."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


class PlaybackTests(unittest.TestCase):
    def test_context_playback_is_repeatable(self):
        reports = []
        for _ in range(2):
            result = subprocess.run(
                [sys.executable, str(PACKAGE / "scripts/demo.py")],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(set(report["cases"]), {"matched", "limited", "switched"})
            self.assertFalse(report["cases"]["matched"]["live_execution_ready"])
            self.assertEqual(report["cases"]["switched"]["rejected"], "context_mismatch")
            reports.append(report)
        self.assertEqual(reports[0], reports[1])

    def test_optimized_mode_keeps_semantic_checks_enabled(self):
        bad_report = {
            "live_execution_ready": False,
            "network_requests": 0,
            "evidence_origin": "sanitized_offline_export",
            "cluster_identity": {"status": "wrong"},
            "namespaces": [{"namespace": "payments", "status": "accessible"}],
            "blockers": [],
        }
        demo = PACKAGE / "scripts/demo.py"
        code = (
            "import importlib.util\n"
            f"spec = importlib.util.spec_from_file_location('kube_demo', {str(demo)!r})\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            f"module.run_case = lambda *args, **kwargs: {bad_report!r}\n"
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
        self.assertIn("cluster identity did not match", result.stderr)
