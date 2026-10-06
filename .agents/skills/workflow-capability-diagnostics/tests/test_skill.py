# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Tests for workflow-capability-diagnostics contributor skill."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.diagnostics import (
    detect_system_platform,
    diagnose_host_tools,
    diagnose_plugin_package,
    run_diagnostics,
)


class TestWorkflowCapabilityDiagnosticsSkill(unittest.TestCase):
    def test_system_detection(self):
        sys_diag = detect_system_platform()
        self.assertIn(sys_diag.os, ["darwin", "linux", "windows"])
        self.assertTrue(len(sys_diag.python_version) > 0)

    def test_tool_diagnostics(self):
        tools = diagnose_host_tools()
        self.assertTrue(len(tools) >= 5)
        tool_names = [t.tool for t in tools]
        self.assertIn("python3", tool_names)
        self.assertIn("nmap", tool_names)

    def test_package_diagnostics(self):
        pkg_dir = ROOT / "plugins" / "offensive-security" / "offensive-engagement-workbench"
        pkg_diag = diagnose_plugin_package(pkg_dir)
        self.assertEqual(pkg_diag.package_id, "offensive-engagement-workbench")
        self.assertIn(pkg_diag.status, ["ready", "degraded"])

    def test_run_diagnostics_report(self):
        report = run_diagnostics(ROOT, strict=False)
        self.assertIsNotNone(report.timestamp)
        self.assertTrue(report.system.is_supported)
        self.assertTrue(report.capability_truth_passed)
        self.assertEqual(report.capability_count, 69)
        self.assertTrue(len(report.packages) >= 14)


if __name__ == "__main__":
    unittest.main()
