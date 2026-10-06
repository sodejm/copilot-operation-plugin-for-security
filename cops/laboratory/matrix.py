"""Tested platform, distribution, runtime, and tool-version matrix validation."""

from __future__ import annotations

import re
from typing import Any

from .models import PrerequisiteMismatchError, TestedMatrix

VERSION_PATTERN = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Parse a semantic or dotted version string into an integer tuple for comparison."""
    clean = version_str.strip().lstrip("vV")
    # Strip any suffix like -rc1 or +build
    clean = re.split(r"[-+]", clean)[0]
    parts: list[int] = []
    for part in clean.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def version_ge(actual: str, minimum: str) -> bool:
    """Return True if actual version is greater than or equal to minimum version."""
    return parse_version_tuple(actual) >= parse_version_tuple(minimum)


def verify_platform_matrix(
    platform: dict[str, Any],
    matrix: TestedMatrix | None = None,
) -> list[str]:
    """Verify that a platform dictionary matches the tested OS, distribution, and runtime matrix.

    Raises PrerequisiteMismatchError on mismatch.
    """
    mat = matrix or TestedMatrix()
    errors: list[str] = []

    os_val = str(platform.get("os", "")).lower()
    if os_val not in mat.supported_os:
        errors.append(
            f"Unsupported operating system '{os_val}'; tested platforms are: {', '.join(mat.supported_os)}"
        )

    dist_val = str(platform.get("distribution", "")).lower()
    if dist_val not in mat.supported_distributions:
        errors.append(
            f"Unsupported distribution '{dist_val}'; tested distributions are: {', '.join(mat.supported_distributions)}"
        )

    arch_val = str(platform.get("architecture", "")).lower()
    if arch_val not in mat.supported_architectures:
        errors.append(
            f"Unsupported architecture '{arch_val}'; tested architectures are: {', '.join(mat.supported_architectures)}"
        )

    runtime_val = str(platform.get("runtime", "")).lower()
    if runtime_val not in mat.supported_runtimes:
        errors.append(
            f"Unsupported laboratory runtime '{runtime_val}'; tested runtimes are: {', '.join(mat.supported_runtimes)}"
        )

    if errors:
        raise PrerequisiteMismatchError("; ".join(errors))

    return [f"Platform {os_val}/{dist_val} ({arch_val}) on {runtime_val} verified against tested matrix."]


def verify_tool_prerequisites(
    tool_matrix: dict[str, str],
    required_tools: list[str] | tuple[str, ...] | None = None,
    matrix: TestedMatrix | None = None,
) -> list[str]:
    """Verify that installed tools satisfy version constraints and presence requirements.

    Raises PrerequisiteMismatchError on missing tools or version mismatches.
    """
    mat = matrix or TestedMatrix()
    errors: list[str] = []
    verified: list[str] = []

    # Check required tools presence
    if required_tools:
        for tool in required_tools:
            if tool not in tool_matrix:
                errors.append(f"Required tool '{tool}' is missing from laboratory environment tool matrix")

    # Check version constraints for all declared tools
    for tool_name, installed_version in tool_matrix.items():
        min_ver = mat.tool_minimum_versions.get(tool_name)
        if min_ver:
            if not version_ge(installed_version, min_ver):
                errors.append(
                    f"Tool '{tool_name}' version '{installed_version}' is below tested minimum '{min_ver}'"
                )
            else:
                verified.append(f"Tool '{tool_name}' v{installed_version} satisfies minimum v{min_ver}")
        else:
            verified.append(f"Tool '{tool_name}' v{installed_version} registered (unconstrained)")

    if errors:
        raise PrerequisiteMismatchError("; ".join(errors))

    return verified
