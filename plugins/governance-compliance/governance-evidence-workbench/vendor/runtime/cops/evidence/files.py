"""Descriptor-relative file boundaries shared by evidence import and lab copy."""

from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path, PurePosixPath


def relative_parts(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("invalid_relative_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("invalid_relative_path")
    return path.parts


def open_root(root: Path, stack: ExitStack) -> int:
    """Open every ancestor without following symlinks; caller closes the stack."""
    absolute = Path(root).absolute()
    if ".." in absolute.parts:
        raise ValueError("invalid_root_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor, flags)
    stack.callback(os.close, descriptor)
    for component in absolute.parts[1:]:
        descriptor = os.open(component, flags, dir_fd=descriptor)
        stack.callback(os.close, descriptor)
    return descriptor


def open_parent(root_fd: int, parts: tuple[str, ...], stack: ExitStack) -> int:
    descriptor = root_fd
    for component in parts[:-1]:
        descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        stack.callback(os.close, descriptor)
    return descriptor


def file_identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
