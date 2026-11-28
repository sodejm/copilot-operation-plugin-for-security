"""Operator-only standalone export. This writer is never registered as a tool."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cops.portable import PORTABLE_ENTRIES, _tracked_files

ROOT = Path(__file__).resolve().parents[2]
SOC = Path("plugins/detection-hunting/soc-investigation-workbench")
_RUNTIME_FILES = {"__init__.py", "_filesystem.py", "_schema_validation.py"}
_RUNTIME_PACKAGES = {"adapters", "assessments", "contracts", "evidence", "mcp", "operations"}


def build_bundle(destination: Path, *, root: Path = ROOT):
    """Create a new directory; never overwrite or follow source symlinks."""
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination_exists")
    # Never enumerate inside a destination created under a source runtime tree.
    for relative in (Path("cops"), Path("catalog"), SOC):
        if destination.resolve().is_relative_to((root / relative).resolve()):
            raise ValueError("destination_inside_source")
    sources = []
    # Like portable plugin exports, use the reviewed Git inventory, never rglob
    # private/untracked files that happen to be under a runtime directory.
    for relative in _tracked_files(root):
        selected = relative.is_relative_to("catalog/schemas")
        if relative.is_relative_to("cops"):
            runtime_path = relative.relative_to("cops")
            selected = runtime_path.as_posix() in _RUNTIME_FILES or (
                len(runtime_path.parts) > 1
                and runtime_path.parts[0] in _RUNTIME_PACKAGES
                and runtime_path.as_posix() != "operations/bundle.py"
            )
        if relative.is_relative_to(SOC):
            selected = relative.relative_to(SOC).parts[0] in PORTABLE_ENTRIES
        selected = selected or relative.as_posix() in {
            "catalog/operations.json",
            "catalog/features.json",
            "catalog/plugins.json",
            "agents/registry.json",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
        }
        if not selected:
            continue
        path = root / relative
        if path.is_symlink() or any((root / parent).is_symlink() for parent in relative.parents):
            raise ValueError("source_symlink")
        if not path.is_file():
            raise ValueError("source_missing")
        sources.append(path)
    destination.mkdir(mode=0o700)
    hashes = {}
    for source in sources:
        relative = source.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = source.read_bytes()
        with target.open("xb") as stream:
            stream.write(raw)
        hashes[relative.as_posix()] = hashlib.sha256(raw).hexdigest()
    launcher = destination / "cops_headless.py"
    launcher.write_text(
        '"""Standalone COPS headless launcher; run from any working directory."""\n'
        "import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).resolve().parent))\n"
        'if sys.argv[1:] == ["mcp"]:\n    from cops.mcp.server import main\n'
        "else:\n    from cops.operations.cli import main\nraise SystemExit(main())\n"
    )
    hashes[launcher.name] = hashlib.sha256(launcher.read_bytes()).hexdigest()
    (destination / "requirements-mcp.txt").write_text("mcp==1.30.0\n")
    hashes["requirements-mcp.txt"] = hashlib.sha256((destination / "requirements-mcp.txt").read_bytes()).hexdigest()
    (destination / "bundle-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "cops.headless-bundle/v1",
                "files": hashes,
                "limitations": [
                    "Hash inventory establishes consistency, not publisher authenticity.",
                    "No live-service, host installation, or controlled-execution readiness claim.",
                ],
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    return hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory; operator-selected, not tool input")
    args = parser.parse_args()
    hashes = build_bundle(args.output)
    print(json.dumps({"status": "exported", "files": len(hashes)}))


if __name__ == "__main__":
    main()
