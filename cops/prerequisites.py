"""Explicit, shell-free installation of declared external tool prerequisites."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from typing import Any, Callable


MANAGERS = {
    "darwin": ("brew",),
    "linux": ("apt-get", "dnf", "brew"),
    "win32": ("winget",),
}
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class PrerequisiteError(ValueError):
    """Invalid declaration or unavailable prerequisite."""


def validate_prerequisites(document: Any, location: str) -> list[dict[str, Any]]:
    """Validate data before it can become a package-manager argument."""

    if not isinstance(document, dict) or set(document) != {"schema_version", "tools"}:
        raise PrerequisiteError(f"{location} must contain only schema_version and tools")
    if document["schema_version"] != "1.0" or not isinstance(document["tools"], list):
        raise PrerequisiteError(f"{location} requires schema_version 1.0 and a tools array")
    seen: set[str] = set()
    for index, tool in enumerate(document["tools"]):
        item = f"{location}.tools[{index}]"
        if not isinstance(tool, dict) or set(tool) != {"id", "command", "packages"}:
            raise PrerequisiteError(f"{item} must contain only id, command, and packages")
        for field in ("id", "command"):
            value = tool[field]
            if not isinstance(value, str) or not TOKEN.fullmatch(value):
                raise PrerequisiteError(f"{item}.{field} must be a safe executable token")
        if tool["id"] in seen:
            raise PrerequisiteError(f"{item}.id duplicates {tool['id']}")
        seen.add(tool["id"])
        packages = tool["packages"]
        if not isinstance(packages, dict) or not packages or set(packages) - {
            manager for choices in MANAGERS.values() for manager in choices
        }:
            raise PrerequisiteError(f"{item}.packages must map supported managers to package ids")
        for manager, package in packages.items():
            if not isinstance(package, str) or not TOKEN.fullmatch(package):
                raise PrerequisiteError(f"{item}.packages.{manager} must be a safe package id")
    return document["tools"]


def install_command(tool: dict[str, Any], platform: str,
                    which: Callable[[str], str | None] = shutil.which) -> list[str]:
    """Choose an available manager; never interpret declarations through a shell."""

    for manager in MANAGERS.get(platform, ()):
        package = tool["packages"].get(manager)
        if package and which(manager):
            if manager == "winget":
                return ["winget", "install", "--id", package, "--exact",
                        "--accept-source-agreements", "--accept-package-agreements"]
            if manager == "apt-get":
                return ["apt-get", "install", "-y", package]
            if manager == "dnf":
                return ["dnf", "install", "-y", package]
            return ["brew", "install", package]
    raise PrerequisiteError(
        f"no supported installed package manager can provide {tool['id']} on {platform}"
    )


def process_tools(tools: list[dict[str, Any]], *, install: bool = False,
                  dry_run: bool = False, platform: str | None = None,
                  which: Callable[[str], str | None] = shutil.which,
                  run: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run) -> list[str]:
    """Report missing tools; install only with an explicit opt-in flag."""

    missing: list[str] = []
    planned: list[tuple[dict[str, Any], list[str]]] = []
    for tool in tools:
        if which(tool["command"]):
            continue
        missing.append(tool["id"])
        if not install and not dry_run:
            continue
        command = install_command(tool, platform or sys.platform, which)
        planned.append((tool, command))
    for tool, command in planned:
        if dry_run:
            print("Would run: " + " ".join(command))
            continue
        if which(tool["command"]):
            missing.remove(tool["id"])
            continue
        result = run(command, check=False)
        if result.returncode != 0 or not which(tool["command"]):
            raise PrerequisiteError(f"installation did not provide {tool['command']}")
        missing.remove(tool["id"])
    return missing
