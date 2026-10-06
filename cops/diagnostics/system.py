"""Host system platform and tool prerequisite diagnostics for COPS."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from cops.laboratory.matrix import TestedMatrix, version_ge

from .models import DiagnosticCheck, SystemDiagnostic, ToolDiagnostic

VERSION_EXTRACT_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _detect_linux_distribution() -> str:
    """Detect Linux distribution ID from /etc/os-release."""
    os_release = Path("/etc/os-release")
    if os_release.is_file():
        try:
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if line.startswith("ID="):
                    return line.split("=", 1)[1].strip('"\'').lower()
        except OSError:
            pass
    return "linux"


def detect_system_platform(matrix: TestedMatrix | None = None) -> SystemDiagnostic:
    """Inspect and validate the host operating system, distribution, and architecture."""
    mat = matrix or TestedMatrix()
    sys_os = sys.platform
    raw_os = platform.system().lower()
    if raw_os == "darwin":
        os_name = "darwin"
        dist_name = "darwin"
    elif raw_os == "linux":
        os_name = "linux"
        dist_name = _detect_linux_distribution()
    elif raw_os == "windows":
        os_name = "windows"
        dist_name = "windows"
    else:
        os_name = sys_os
        dist_name = "unknown"

    arch = platform.machine().lower()
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    checks: list[DiagnosticCheck] = []
    is_supported = True

    # OS check
    if os_name in mat.supported_os:
        checks.append(DiagnosticCheck("operating_system", "passed", f"Supported OS: {os_name}"))
    else:
        checks.append(DiagnosticCheck(
            "operating_system", "failed",
            f"Unsupported OS: {os_name}; supported: {', '.join(mat.supported_os)}"
        ))
        is_supported = False

    # Architecture check
    if arch in mat.supported_architectures:
        checks.append(DiagnosticCheck("architecture", "passed", f"Supported architecture: {arch}"))
    else:
        checks.append(DiagnosticCheck(
            "architecture", "failed",
            f"Unsupported architecture: {arch}; supported: {', '.join(mat.supported_architectures)}"
        ))
        is_supported = False

    # Python version check (>= 3.11)
    if sys.version_info >= (3, 11):  # noqa: UP036 - diagnose unsupported Python runtimes
        checks.append(DiagnosticCheck("python_runtime", "passed", f"Python {py_ver} meets >= 3.11 requirement"))
    else:
        checks.append(DiagnosticCheck("python_runtime", "failed", f"Python {py_ver} is older than required 3.11"))
        is_supported = False

    return SystemDiagnostic(
        os=os_name,
        distribution=dist_name,
        architecture=arch,
        python_version=py_ver,
        is_supported=is_supported,
        checks=checks,
    )


def extract_tool_version(output: str) -> str | None:
    """Extract a version substring (e.g. 1.28.0) from CLI output."""
    match = VERSION_EXTRACT_RE.search(output)
    return match.group(1) if match else None


def diagnose_tool(tool_name: str, minimum_version: str) -> ToolDiagnostic:
    """Inspect whether a specific tool is installed and meets version prerequisites."""
    tool_path = shutil.which(tool_name)
    if not tool_path:
        return ToolDiagnostic(
            tool=tool_name,
            status="missing",
            installed_version=None,
            minimum_version=minimum_version,
            path=None,
            notes="Binary not found in PATH",
        )

    # Probe version
    installed_ver: str | None = None
    try:
        # Most security tools respond to --version or -v
        res = subprocess.run(
            [tool_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        combined_output = f"{res.stdout} {res.stderr}"
        installed_ver = extract_tool_version(combined_output)
    except (subprocess.TimeoutExpired, OSError) as err:
        return ToolDiagnostic(
            tool=tool_name,
            status="missing",
            installed_version=None,
            minimum_version=minimum_version,
            path=tool_path,
            notes=f"Failed to query tool version: {err}",
        )

    if not installed_ver:
        return ToolDiagnostic(
            tool=tool_name,
            status="version_mismatch",
            installed_version="unknown",
            minimum_version=minimum_version,
            path=tool_path,
            notes="Could not extract version from tool output",
        )

    if version_ge(installed_ver, minimum_version):
        return ToolDiagnostic(
            tool=tool_name,
            status="available",
            installed_version=installed_ver,
            minimum_version=minimum_version,
            path=tool_path,
            notes="Version prerequisite satisfied",
        )

    return ToolDiagnostic(
        tool=tool_name,
        status="version_mismatch",
        installed_version=installed_ver,
        minimum_version=minimum_version,
        path=tool_path,
        notes=f"Installed version {installed_ver} is below minimum {minimum_version}",
    )


def diagnose_host_tools(
    tool_minimums: dict[str, str] | None = None,
) -> list[ToolDiagnostic]:
    """Diagnose all declared tool prerequisites and report exact availability."""
    mat = TestedMatrix()
    targets = tool_minimums if tool_minimums is not None else mat.tool_minimum_versions
    results: list[ToolDiagnostic] = []
    for tool_name, min_ver in sorted(targets.items()):
        results.append(diagnose_tool(tool_name, min_ver))
    return results
