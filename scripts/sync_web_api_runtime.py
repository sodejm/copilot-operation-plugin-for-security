#!/usr/bin/env python3
"""Synchronize the Web API workbench's package-local Python runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

RUNTIME_MODULES = (
    "catalog/schemas/action-plan.schema.json",
    "cops/__init__.py",
    "cops/contracts/lifecycle.py",
    "cops/contracts/models.py",
    "cops/contracts/validation.py",
    "cops/discovery/models.py",
    "cops/evidence/canonical.py",
    "cops/evidence/validation.py",
    "cops/execution/authorization.py",
    "cops/execution/control.py",
    "cops/execution/scope_guard.py",
    "cops/execution/store.py",
    "cops/web_api/__init__.py",
    "cops/web_api/assessment.py",
    "cops/web_api/cli.py",
    "cops/web_api/importer.py",
    "cops/web_api/laboratory.py",
    "cops/web_api/models.py",
    "cops/web_api/replay.py",
    "cops/web_api/sanitization.py",
    "cops/web_api/websocket.py",
    "cops/web_api/worker_replay.py",
)
MINIMAL_INITIALIZERS = (
    "cops/contracts/__init__.py",
    "cops/discovery/__init__.py",
    "cops/evidence/__init__.py",
    "cops/execution/__init__.py",
)
MANIFEST = "runtime-provenance.json"
MARKER = '"""Package marker for the vendored Web API workbench runtime."""\n'
UNAVAILABLE_WORKER = (
    '"""The portable package does not include a qualified isolated worker."""\n'
    'raise ImportError("live Web API replay requires a separately qualified isolated worker runtime")\n'
)


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _expected(source_root: Path) -> dict[str, bytes]:
    missing = [name for name in RUNTIME_MODULES if not (source_root / name).is_file()]
    if missing:
        raise ValueError(f"runtime source is incomplete: {missing}")
    files = {name: (source_root / name).read_bytes() for name in RUNTIME_MODULES}
    files.update({name: MARKER.encode("utf-8") for name in MINIMAL_INITIALIZERS})
    files["cops/execution/worker.py"] = UNAVAILABLE_WORKER.encode("utf-8")
    records = [
        {
            "path": name,
            "sha256": _digest(content),
            "source": (
                name if name in RUNTIME_MODULES else
                "generated-unavailable-worker" if name == "cops/execution/worker.py" else
                "generated-package-marker"
            ),
        }
        for name, content in sorted(files.items())
    ]
    manifest = {
        "schema_version": "cops.vendored-python-runtime/v1",
        "purpose": "offline Web API workbench execution from an installed portable package",
        "files": records,
    }
    files[MANIFEST] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return files


def _actual_files(destination: Path) -> set[str]:
    if not destination.exists():
        return set()
    return {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def synchronize(source_root: Path, destination: Path, *, check: bool) -> list[str]:
    """Write or verify the exact reviewed runtime inventory."""

    expected = _expected(source_root)
    actual = _actual_files(destination)
    unexpected = actual - set(expected)
    if unexpected:
        raise ValueError(f"vendored runtime has unexpected files: {sorted(unexpected)}")
    stale = [
        name
        for name, content in expected.items()
        if not (destination / name).is_file() or (destination / name).read_bytes() != content
    ]
    if check:
        if stale:
            raise ValueError(f"vendored runtime is stale or incomplete: {stale}")
        return []
    for name in stale:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(expected[name])
    return stale


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=root)
    parser.add_argument(
        "--destination",
        type=Path,
        default=root / "plugins/offensive-security/web-api-assessment-workbench/vendor",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        changed = synchronize(args.source_root.resolve(), args.destination.resolve(), check=args.check)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if changed:
        print("synchronized " + ", ".join(changed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
