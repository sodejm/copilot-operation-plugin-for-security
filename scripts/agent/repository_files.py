"""Enumerate repository sources without inspecting ignored local artifacts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


ARCHIVE_EXCLUDES = {
    ".git", ".venv", "venv", "env", "ENV", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist", ".tmp", "tmp",
}


def repository_files(root: Path) -> list[Path]:
    """Include tracked and new sources, never dereferencing a symlink.

    Git remains authoritative for checkouts, including tracked ignored files.
    Source archives use a conservative directory filter without needing Git.
    """
    root = root.resolve()
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, capture_output=True, check=True,
        )
        candidates = {root / os.fsdecode(name) for name in result.stdout.split(b"\0") if name}
    else:
        candidates = set()
        for directory, subdirs, filenames in os.walk(root, followlinks=False):
            parent = Path(directory)
            subdirs[:] = [
                name for name in subdirs
                if name not in ARCHIVE_EXCLUDES and not (parent / name).is_symlink()
            ]
            candidates.update(parent / name for name in filenames)
    return sorted(
        path for path in candidates
        if path.is_relative_to(root)
        and not any(part.is_symlink() for part in (path, *path.parents) if part != root)
        and path.is_file()
    )
