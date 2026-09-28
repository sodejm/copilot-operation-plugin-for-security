#!/usr/bin/env python3
"""Verify contributor test requirements using the selected interpreter, offline."""

from __future__ import annotations

import re
import sys
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIREMENT = re.compile(r"([A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*)(?:\s*>=\s*(\d+(?:\.\d+)*))?")
RELEASE = re.compile(r"(\d+(?:\.\d+)*)(?:\.post\d+)?")


def read_requirements(path: Path) -> list[tuple[str, str | None]]:
    requirements = []
    seen = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        declaration = line.split("#", 1)[0].strip()
        if not declaration:
            continue
        match = REQUIREMENT.fullmatch(declaration)
        if not match:
            raise ValueError(f"requirements.txt:{number}: expected a name or name>=numeric.version")
        name, minimum = match.groups()
        name = name.lower().replace("_", "-")
        if name in seen:
            raise ValueError(f"requirements.txt:{number}: duplicate dependency {name}")
        seen.add(name)
        requirements.append((name, minimum))
    if not requirements:
        raise ValueError("requirements.txt: no test dependencies declared")
    return requirements


def release_tuple(value: str) -> tuple[int, ...]:
    match = RELEASE.fullmatch(value)
    if not match:
        raise ValueError("expected a stable numeric release")
    parts = tuple(int(part) for part in match[1].split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def check_prerequisites(root: Path = ROOT) -> bool:
    environment = "virtual environment" if sys.prefix != sys.base_prefix else "selected interpreter"
    print(f"Python {'.'.join(map(str, sys.version_info[:3]))}: {sys.executable} ({environment})", flush=True)
    errors = []
    requirements = []
    if sys.version_info < (3, 11):
        errors.append("Python 3.11 or newer is required for contributor checks")
    else:
        try:
            requirements = read_requirements(root / "requirements.txt")
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"cannot read test requirements: {error}")
    for name, minimum in requirements:
        try:
            installed = version(name)
        except PackageNotFoundError:
            errors.append(f"{name}: missing")
            continue
        try:
            installed_release = release_tuple(installed)
        except ValueError:
            errors.append(f"{name}: installed {installed}, expected a stable numeric release")
            continue
        if minimum and installed_release < release_tuple(minimum):
            errors.append(f"{name}: installed {installed}, requires >={minimum}")
            continue
        module = name.replace("-", "_")
        try:
            import_module(module)
        except Exception as error:
            errors.append(f"{name}: cannot import {module} ({type(error).__name__})")
            continue
        print(f"  {name} {installed}: importable", flush=True)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print("Create and activate a Python 3.11+ virtual environment, then run:\n"
              "  python -m pip install -r requirements.txt\n"
              "Offline setup and troubleshooting: CONTRIBUTING.md", file=sys.stderr)
        return False
    print("Test prerequisites are ready; verification did not install dependencies.", flush=True)
    return True


if __name__ == "__main__":
    raise SystemExit(0 if check_prerequisites() else 1)
