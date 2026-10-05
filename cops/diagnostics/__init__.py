"""COPS package workflows and capability diagnostics runtime."""

from __future__ import annotations

from .models import (
    DiagnosticCheck,
    DiagnosticReport,
    DiagnosticStatus,
    PackageDiagnostic,
    SystemDiagnostic,
    ToolDiagnostic,
)
from .packages import diagnose_packages, diagnose_plugin_package
from .runner import run_diagnostics
from .system import detect_system_platform, diagnose_host_tools, diagnose_tool

__all__ = [
    "DiagnosticCheck",
    "DiagnosticReport",
    "DiagnosticStatus",
    "PackageDiagnostic",
    "SystemDiagnostic",
    "ToolDiagnostic",
    "detect_system_platform",
    "diagnose_host_tools",
    "diagnose_packages",
    "diagnose_plugin_package",
    "diagnose_tool",
    "run_diagnostics",
]
