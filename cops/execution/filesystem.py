"""Compatibility imports for directory-descriptor helpers."""

from cops._filesystem import (
    SecureDirectoryError,
    create_directory_exclusive_no_symlinks,
    open_directory_no_symlinks,
    same_directory_identity,
)

__all__ = [
    "SecureDirectoryError",
    "create_directory_exclusive_no_symlinks",
    "open_directory_no_symlinks",
    "same_directory_identity",
]
