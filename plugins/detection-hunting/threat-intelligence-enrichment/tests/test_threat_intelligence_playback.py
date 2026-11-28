from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def load_demo_module():
    script = PACKAGE_ROOT / "scripts" / "run_demo.py"
    spec = importlib.util.spec_from_file_location("threat_intelligence_run_demo", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load playback runner: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        self.assertEqual(result["request_attempts"], {"misp": 1, "taxii": 1, "microsoft": 3})
        self.assertEqual(result["misp"]["initial"]["status"], "positive")
        self.assertTrue(result["misp"]["initial"]["conflicts"])
        self.assertEqual(result["misp"]["fresh_cache"]["cache"], "fresh")
        self.assertEqual(result["misp"]["stale_cache"]["cache"], "stale")
        self.assertEqual(result["misp"]["as_of_replay"]["cache"], "fresh")
        self.assertEqual(result["taxii_partial"]["status"], "partial")
        self.assertEqual(result["taxii_partial"]["error"], "pagination_limit")
        self.assertEqual(result["microsoft_failure"]["status"], "error")
        self.assertEqual(result["microsoft_failure"]["error"], "http_503")

    def test_demo_rejects_shortened_microsoft_retry_sequence(self) -> None:
        demo = load_demo_module()
        production_enrich = demo.enrich

        def shortened_retry_enrich(indicator, source, approval, **kwargs):
            if source.name != "microsoft":
                return production_enrich(indicator, source, approval, **kwargs)

            transport = kwargs["transport_factory"](
                source.origin,
                f"{source.path}/{indicator.value}",
                "GET",
            )
            for _ in range(2):
                response = transport.send(object(), {}, timeout=10, max_bytes=1)
                self.assertEqual(response.status, 503)
            return {
                "status": "error",
                "error": "http_503",
                "claims": [],
                "conflicts": [],
                "cache": None,
            }

        output = io.StringIO()
        with mock.patch.object(demo, "enrich", side_effect=shortened_retry_enrich):
            with contextlib.redirect_stdout(output):
                with self.assertRaisesRegex(
                    demo.PlaybackError,
                    "provider request-attempt evidence is invalid",
                ):
                    demo.main()

        self.assertEqual(output.getvalue(), "")
