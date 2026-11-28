"""Durable, owner-only evidence storage for laboratory execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cops.evidence.canonical import canonical
from cops.execution.filesystem import SecureDirectoryError, open_directory_no_symlinks

from .models import LaboratoryGateError

_SAFE_KIND = re.compile(r"[^a-z0-9_-]+")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class LaboratoryEvidenceStore:
    """Write immutable canonical JSON outside disposable worker workspaces."""

    def __init__(self, directory: Path | str) -> None:
        candidate = Path(directory)
        if not candidate.is_absolute():
            raise LaboratoryGateError("laboratory evidence directory path must be absolute")
        self.directory = Path(os.path.abspath(os.fspath(candidate)))
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as err:
            raise LaboratoryGateError("cannot create laboratory evidence directory") from err
        descriptor = self._open_checked_directory()
        os.close(descriptor)

    def _open_checked_directory(self) -> int:
        """Open and validate the destination while retaining its directory handle."""
        descriptor = -1
        try:
            descriptor = open_directory_no_symlinks(self.directory)
            directory_stat = os.fstat(descriptor)
            if hasattr(os, "geteuid") and directory_stat.st_uid != os.geteuid():
                raise LaboratoryGateError("laboratory evidence directory must be owned by the operator")
            if stat.S_IMODE(directory_stat.st_mode) & 0o077:
                raise LaboratoryGateError("laboratory evidence directory must be owner-only")
            return descriptor
        except (OSError, SecureDirectoryError) as err:
            if descriptor >= 0:
                os.close(descriptor)
            raise LaboratoryGateError("cannot protect laboratory evidence directory") from err
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            raise

    def _validate_directory_binding(self, descriptor: int) -> None:
        """Require the configured path to still name the held directory."""
        held = os.fstat(descriptor)
        try:
            current = os.stat(self.directory, follow_symlinks=False)
        except OSError as err:
            raise LaboratoryGateError("laboratory evidence directory changed during write") from err
        if not stat.S_ISDIR(current.st_mode) or current.st_dev != held.st_dev or current.st_ino != held.st_ino:
            raise LaboratoryGateError("laboratory evidence directory changed during write")

    @staticmethod
    def _validate_file(descriptor: int) -> os.stat_result:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise LaboratoryGateError("laboratory evidence must be a regular file")
        if hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid():
            raise LaboratoryGateError("laboratory evidence must be owned by the operator")
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise LaboratoryGateError("laboratory evidence must be owner-only")
        return file_stat

    @staticmethod
    def _read_all(descriptor: int) -> bytes:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    @staticmethod
    def _remove_incomplete(directory_descriptor: int, name: str, created: os.stat_result) -> None:
        """Remove only the file created by this write attempt."""
        try:
            current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if current.st_dev == created.st_dev and current.st_ino == created.st_ino:
                os.unlink(name, dir_fd=directory_descriptor)
                os.fsync(directory_descriptor)
        except OSError:
            pass

    def write_json(self, kind: str, value: Any) -> dict[str, Any]:
        """Persist canonical bytes and return a digest-backed artifact reference."""
        raw = canonical(value)
        digest = hashlib.sha256(raw).hexdigest()
        safe_kind = _SAFE_KIND.sub("-", kind.lower()).strip("-") or "evidence"
        name = f"{safe_kind}-{digest}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_descriptor = self._open_checked_directory()
        descriptor = -1
        created: os.stat_result | None = None
        try:
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
                created = self._validate_file(descriptor)
            except FileExistsError:
                read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    read_flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(name, read_flags, dir_fd=directory_descriptor)
                    self._validate_file(descriptor)
                    existing = self._read_all(descriptor)
                except (OSError, LaboratoryGateError) as err:
                    raise LaboratoryGateError("cannot safely read existing laboratory evidence") from err
                if existing != raw:
                    raise LaboratoryGateError("laboratory evidence digest collision") from None
                self._validate_directory_binding(directory_descriptor)
                return {
                    "kind": safe_kind,
                    "path": name,
                    "sha256": digest,
                    "byte_length": len(raw),
                }
            except (OSError, LaboratoryGateError) as err:
                raise LaboratoryGateError("cannot create laboratory evidence") from err

            try:
                offset = 0
                while offset < len(raw):
                    written = os.write(descriptor, raw[offset:])
                    if written <= 0:
                        raise OSError("laboratory evidence write made no progress")
                    offset += written
                os.fsync(descriptor)
                os.fsync(directory_descriptor)
                self._validate_directory_binding(directory_descriptor)
            except (OSError, LaboratoryGateError) as err:
                if created is not None:
                    self._remove_incomplete(directory_descriptor, name, created)
                if isinstance(err, LaboratoryGateError):
                    raise
                raise LaboratoryGateError("cannot write laboratory evidence") from err
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory_descriptor)
        return {
            "kind": safe_kind,
            "path": name,
            "sha256": digest,
            "byte_length": len(raw),
        }

    def resolve(self, reference: Mapping[str, Any]) -> Path:
        """Resolve a validated content-addressed reference under this store."""
        kind = reference.get("kind")
        path = reference.get("path")
        digest = reference.get("sha256")
        if (
            not isinstance(kind, str)
            or not kind
            or _SAFE_KIND.sub("-", kind.lower()).strip("-") != kind
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or not isinstance(path, str)
            or path != f"{kind}-{digest}.json"
        ):
            raise LaboratoryGateError("invalid laboratory evidence reference")
        return self.directory / path

    def read_json(self, reference: Mapping[str, Any]) -> Any:
        """Read and authenticate canonical content-addressed evidence bytes."""
        path = self.resolve(reference)
        directory_descriptor = self._open_checked_directory()
        descriptor = -1
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            metadata = self._validate_file(descriptor)
            if metadata.st_size > 4 * 1024 * 1024:
                raise LaboratoryGateError("laboratory evidence exceeds the byte limit")
            raw = self._read_all(descriptor)
            self._validate_directory_binding(directory_descriptor)
        except (OSError, LaboratoryGateError) as err:
            raise LaboratoryGateError("cannot safely read laboratory evidence") from err
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory_descriptor)
        if hashlib.sha256(raw).hexdigest() != reference.get("sha256") or len(raw) != reference.get("byte_length"):
            raise LaboratoryGateError("laboratory evidence digest or length does not match its reference")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as err:
            raise LaboratoryGateError("laboratory evidence is not valid JSON") from err
        if canonical(value) != raw:
            raise LaboratoryGateError("laboratory evidence is not canonically encoded")
        return value
