"""Unit tests for package workflows and capability diagnostics runtime."""

from __future__ import annotations

import json
from pathlib import Path

from cops.diagnostics import (
    DiagnosticReport,
    detect_system_platform,
    diagnose_host_tools,
    diagnose_packages,
    diagnose_plugin_package,
    diagnose_tool,
    run_diagnostics,
)
from cops.diagnostics.cli import command_diagnostics

ROOT = Path(__file__).resolve().parents[1]


def test_detect_system_platform():
    """Verify system platform detection identifies supported environment."""
    sys_diag = detect_system_platform()
    assert sys_diag.os in ("darwin", "linux", "windows")
    assert sys_diag.python_version != ""
    assert isinstance(sys_diag.is_supported, bool)
    d = sys_diag.to_dict()
    assert "os" in d
    assert "python_version" in d
    assert "checks" in d


def test_diagnose_tool():
    """Verify tool diagnosis finds python3 and correctly classifies missing tools."""
    py_tool = diagnose_tool("python3", ">=3.11")
    assert py_tool.status == "available"
    assert py_tool.installed_version is not None

    fake_tool = diagnose_tool("nonexistent_binary_xyz_123", ">=1.0.0")
    assert fake_tool.status == "missing"
    assert fake_tool.installed_version is None


def test_diagnose_host_tools():
    """Verify host tools diagnosis inspects standard security toolset."""
    tools = diagnose_host_tools()
    assert len(tools) >= 5
    tool_map = {t.tool: t for t in tools}
    assert "python3" in tool_map
    assert tool_map["python3"].status == "available"
    assert "nmap" in tool_map


def test_diagnose_plugin_package():
    """Verify package diagnosis for offensive-engagement-workbench."""
    pkg_path = ROOT / "plugins" / "offensive-security" / "offensive-engagement-workbench"
    diag = diagnose_plugin_package(pkg_path)
    assert diag.package_id == "offensive-engagement-workbench"
    assert diag.category == "offensive-security"
    assert diag.manifest_valid is True
    assert diag.skills_count >= 1
    assert diag.has_playbook is True
    assert diag.has_validation_script is True
    assert diag.status in ("ready", "degraded")


def test_diagnose_packages_all():
    """Verify package diagnosis across all plugins in repository."""
    plugins_dir = ROOT / "plugins"
    packages = diagnose_packages(plugins_dir)
    assert len(packages) >= 14
    pkg_ids = [p.package_id for p in packages]
    assert "offensive-engagement-workbench" in pkg_ids
    assert "security-logging-advisor" in pkg_ids


def test_run_diagnostics_report():
    """Verify complete diagnostic report execution."""
    report = run_diagnostics(ROOT, strict=False)
    assert isinstance(report, DiagnosticReport)
    assert report.system.is_supported is True
    assert report.capability_truth_passed is True
    assert report.capability_count == 69
    assert len(report.packages) >= 14
    assert report.all_ready is True

    # Test serialization
    as_dict = report.to_dict()
    assert as_dict["capability_truth_passed"] is True
    assert as_dict["capability_count"] == 69
    assert "system" in as_dict
    assert "tools" in as_dict
    assert "packages" in as_dict
    assert "summary" in as_dict


def test_run_diagnostics_scoped_package():
    """Verify running diagnostics scoped to a single package."""
    report = run_diagnostics(ROOT, package_id="offensive-engagement-workbench")
    assert len(report.packages) == 1
    assert report.packages[0].package_id == "offensive-engagement-workbench"


def test_run_diagnostics_unknown_package():
    """Verify running diagnostics for an unknown package marks it unready."""
    report = run_diagnostics(ROOT, package_id="unknown-fake-package")
    assert len(report.packages) == 1
    assert report.packages[0].package_id == "unknown-fake-package"
    assert report.packages[0].status == "unready"
    assert report.all_ready is False


def test_run_diagnostics_tools_only():
    """Verify running diagnostics in tools_only mode skips packages."""
    report = run_diagnostics(ROOT, tools_only=True)
    assert len(report.packages) == 0
    assert len(report.tools) >= 5


def test_command_diagnostics_cli(capsys):
    """Verify CLI diagnostics command execution."""
    # Normal execution
    code = command_diagnostics(root=ROOT)
    assert code == 0
    captured = capsys.readouterr().out
    assert "Platform:" in captured
    assert "Tool Prerequisites Matrix" in captured
    assert "Plugin Package Workflows" in captured
    assert "Capability Reconciliation" in captured
    assert "Total Audited Capabilities: 69" in captured

    # JSON execution
    code_json = command_diagnostics(root=ROOT, as_json=True)
    assert code_json == 0
    captured_json = capsys.readouterr().out
    data = json.loads(captured_json)
    assert data["capability_truth_passed"] is True
    assert data["capability_count"] == 69

    # Scoped package execution
    code_pkg = command_diagnostics(root=ROOT, package="offensive-engagement-workbench")
    assert code_pkg == 0
    captured_pkg = capsys.readouterr().out
    assert "offensive-engagement-workbench" in captured_pkg
