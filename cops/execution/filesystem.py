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


def create_directory_exclusive_no_symlinks(
    path: Path | str,
    *,
    mode: int = 0o700,
) -> int:
    """Create and open exactly one final directory beneath a verified parent.

    The parent path is opened component by component without following symbolic
    links. The final ``mkdir`` is exclusive, so callers cannot accidentally
    adopt a pre-existing directory as a worker-created resource. The returned
    descriptor remains bound to the new directory for identity persistence.
    """
    requested = Path(path)
    if any(component == ".." for component in requested.parts):
        raise SecureDirectoryError("directory path must not contain '..' components")
    absolute = Path(os.path.abspath(os.fspath(requested)))
    if absolute.name in {"", ".", ".."}:
        raise SecureDirectoryError("directory path must name a final component")

    parent_fd = -1
    try:
        parent_fd = open_directory_no_symlinks(absolute.parent)
        os.mkdir(absolute.name, mode=mode, dir_fd=parent_fd)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        return os.open(absolute.name, flags, dir_fd=parent_fd)
    except OSError as err:
        raise SecureDirectoryError(
            f"directory path cannot be created exclusively without following symbolic links: {absolute}"
        ) from err
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
