"""Directory-descriptor helpers for workspace-confined filesystem access."""

from __future__ import annotations

import os
from pathlib import Path


class SecureDirectoryError(OSError):
    """A directory path could not be opened without following symbolic links."""


def open_directory_no_symlinks(
    path: Path | str,
    *,
    create: bool = False,
    mode: int = 0o700,
) -> int:
    """Open a directory path without following any symbolic-link component."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SecureDirectoryError(
            "symlink-safe directory access requires POSIX O_NOFOLLOW and directory descriptors"
        )

    requested = Path(path)
    if any(component == ".." for component in requested.parts):
        raise SecureDirectoryError("directory path must not contain '..' components")

    absolute = Path(os.path.abspath(os.fspath(requested)))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(absolute.anchor, flags)
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=mode, dir_fd=descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as err:
        if descriptor >= 0:
            os.close(descriptor)
        raise SecureDirectoryError(
            f"directory path cannot be accessed without following symbolic links: {absolute}"
        ) from err
