"""Substitution-resistant executable preparation for registered adapters."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from cops.adapters import ToolAdapter

from .process import run_bounded_process


class ExecutableVerificationError(RuntimeError):
    """The worker could not establish the adapter executable's identity."""


class ExecutablePreparationTimeoutError(ExecutableVerificationError):
    """Executable staging or version verification exhausted the step deadline."""


def _normalize_revision(value: str) -> str:
    """Normalize the catalog's optional release-tag prefix for comparison."""
    return value[1:] if value[:1].lower() == "v" else value


def _required_posix_flags() -> tuple[int, int]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ExecutableVerificationError(
            "stable executable identity requires POSIX O_NOFOLLOW and directory-descriptor support"
        )
    return os.O_NOFOLLOW, os.O_DIRECTORY


def _validate_private_directory(fd: int, label: str) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise ExecutableVerificationError(f"{label} is not a directory")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ExecutableVerificationError(f"{label} is not owned by the worker account")
    if info.st_mode & 0o022:
        raise ExecutableVerificationError(f"{label} is writable by group or other users")


def _check_preparation_deadline(deadline: float) -> None:
    if monotonic() >= deadline:
        raise ExecutablePreparationTimeoutError(
            "adapter executable preparation exceeded the step timeout"
        )


def _copy_from_open_descriptor(
    source_fd: int,
    destination_fd: int,
    max_size_bytes: int,
    *,
    deadline: float,
) -> str:
    """Copy and digest bytes from an already-open source descriptor."""
    hasher = hashlib.sha256()
    copied = 0
    while True:
        _check_preparation_deadline(deadline)
        chunk = os.read(source_fd, 65_536)
        if not chunk:
            break
        copied += len(chunk)
        if copied > max_size_bytes:
            raise ExecutableVerificationError(
                f"executable exceeds adapter max_size_bytes ({copied} > {max_size_bytes})"
            )
        hasher.update(chunk)
        view = memoryview(chunk)
        while view:
            _check_preparation_deadline(deadline)
            written = os.write(destination_fd, view)
            view = view[written:]
    _check_preparation_deadline(deadline)
    os.fsync(destination_fd)
    _check_preparation_deadline(deadline)
    return hasher.hexdigest()


@dataclass
class PreparedExecutable:
    path: Path
    source_path: Path
    sha256: str
    version: str
    provenance: Mapping[str, str]
    staging_dir: Path
    filename: str
    descriptor: int

    @property
    def invocation_path(self) -> str:
        """Return the child-visible path bound to the held executable descriptor."""
        return f"/proc/self/fd/{self.descriptor}"

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (self.descriptor,)

    def remove(self) -> None:
        """Remove the staged executable through its protected directory."""
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        nofollow, directory = _required_posix_flags()
        try:
            dir_fd = os.open(self.staging_dir, os.O_RDONLY | directory | nofollow)
        except FileNotFoundError:
            return
        try:
            _validate_private_directory(dir_fd, "executable staging directory")
            try:
                os.unlink(self.filename, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        finally:
            os.close(dir_fd)
        try:
            self.staging_dir.rmdir()
        except OSError:
            pass


def prepare_executable(
    adapter: ToolAdapter,
    *,
    workspace: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    deadline: float | None = None,
) -> PreparedExecutable:
    """Open, stage, digest, version-check, and return an adapter executable.

    The source pathname is used only to obtain an ``O_NOFOLLOW`` descriptor.
    All verified and invoked bytes come from the worker-owned staged copy.
    """
    preparation_deadline = deadline if deadline is not None else monotonic() + timeout_seconds
    nofollow, directory = _required_posix_flags()
    if not Path("/proc/self/fd").is_dir():
        raise ExecutableVerificationError(
            "substitution-resistant executable launch requires Linux /proc/self/fd support"
        )
    verification = adapter.executable_verification
    if verification is None or verification.sha256 is None:
        raise ExecutableVerificationError(
            f"adapter '{adapter.tool}' has no platform-specific pinned executable sha256"
        )
    missing_provenance = [
        key for key in ("source", "license", "pinned_revision") if not adapter.provenance.get(key, "").strip()
    ]
    if missing_provenance:
        raise ExecutableVerificationError(
            f"adapter '{adapter.tool}' is missing provenance fields: {missing_provenance}"
        )

    located = shutil.which(adapter.binary, path=env.get("PATH"))
    if located is None:
        raise ExecutableVerificationError(f"adapter executable '{adapter.binary}' was not found")
    source_path = Path(located).absolute()

    try:
        source_fd = os.open(source_path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError as err:
        raise ExecutableVerificationError(
            f"adapter executable '{source_path}' could not be opened without following symlinks: {err}"
        ) from err

    workspace_fd = -1
    stage_fd = -1
    destination_fd = -1
    executable_fd = -1
    filename = f"{re.sub(r'[^a-zA-Z0-9_-]', '_', adapter.tool)}-{uuid.uuid4().hex}"
    staging_dir = workspace / ".executables"
    try:
        source_before = os.fstat(source_fd)
        if not stat.S_ISREG(source_before.st_mode):
            raise ExecutableVerificationError("adapter executable is not a regular file")
        if source_before.st_mode & 0o111 == 0:
            raise ExecutableVerificationError("adapter executable is not executable")

        workspace_fd = os.open(workspace, os.O_RDONLY | directory | nofollow)
        _validate_private_directory(workspace_fd, "worker workspace")
        try:
            os.mkdir(".executables", mode=0o700, dir_fd=workspace_fd)
        except FileExistsError:
            pass
        stage_fd = os.open(".executables", os.O_RDONLY | directory | nofollow, dir_fd=workspace_fd)
        _validate_private_directory(stage_fd, "executable staging directory")
        destination_fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
            0o700,
            dir_fd=stage_fd,
        )
        actual_sha256 = _copy_from_open_descriptor(
            source_fd,
            destination_fd,
            verification.max_size_bytes,
            deadline=preparation_deadline,
        )
        os.fchmod(destination_fd, 0o500)
        staged_before = os.fstat(destination_fd)
        source_after = os.fstat(source_fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if any(getattr(source_before, field) != getattr(source_after, field) for field in stable_fields):
            raise ExecutableVerificationError("adapter executable changed while its bytes were staged")
        if actual_sha256 != verification.sha256:
            raise ExecutableVerificationError(
                f"adapter executable digest mismatch: expected {verification.sha256}, got {actual_sha256}"
            )
        os.close(destination_fd)
        destination_fd = -1
        executable_fd = os.open(
            filename,
            os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=stage_fd,
        )
        staged_after = os.fstat(executable_fd)
        if (staged_before.st_dev, staged_before.st_ino, staged_before.st_size) != (
            staged_after.st_dev,
            staged_after.st_ino,
            staged_after.st_size,
        ):
            raise ExecutableVerificationError("staged executable was substituted before launch binding")
    except Exception:
        if executable_fd >= 0:
            os.close(executable_fd)
            executable_fd = -1
        if stage_fd >= 0:
            try:
                os.unlink(filename, dir_fd=stage_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        for fd in (destination_fd, stage_fd, workspace_fd, source_fd):
            if fd >= 0:
                os.close(fd)

    staged_path = staging_dir / filename
    prepared: PreparedExecutable | None = None
    try:
        remaining_time = preparation_deadline - monotonic()
        if remaining_time <= 0:
            raise ExecutablePreparationTimeoutError(
                "adapter executable preparation exceeded the step timeout"
            )
        version_result = run_bounded_process(
            [f"/proc/self/fd/{executable_fd}", *verification.version_args],
            cwd=workspace,
            env=env,
            timeout_seconds=min(remaining_time, 5),
            max_output_bytes=65_536,
            pass_fds=(executable_fd,),
        )
        if version_result.timed_out:
            raise ExecutablePreparationTimeoutError("adapter executable version probe timed out")
        if version_result.output_limit_exceeded:
            raise ExecutableVerificationError("adapter executable version probe exceeded 65536 bytes")
        if version_result.returncode != 0:
            raise ExecutableVerificationError(
                f"adapter executable version probe exited with code {version_result.returncode}"
            )
        version_text = (version_result.stdout + b"\n" + version_result.stderr).decode(
            "utf-8", errors="replace"
        )
        match = re.search(verification.version_pattern, version_text)
        if match is None:
            raise ExecutableVerificationError("adapter executable version output did not match its contract")
        actual_version = match.groupdict().get("version") or match.group(1)
        expected_version = adapter.provenance["pinned_revision"]
        if _normalize_revision(actual_version) != _normalize_revision(expected_version):
            raise ExecutableVerificationError(
                "adapter executable version mismatch: "
                f"expected provenance revision {expected_version}, got {actual_version}"
            )
        prepared = PreparedExecutable(
            path=staged_path,
            source_path=source_path,
            sha256=actual_sha256,
            version=actual_version,
            provenance=dict(adapter.provenance),
            staging_dir=staging_dir,
            filename=filename,
            descriptor=executable_fd,
        )
        executable_fd = -1
        return prepared
    finally:
        if prepared is None:
            provisional = PreparedExecutable(
                path=staged_path,
                source_path=source_path,
                sha256=verification.sha256,
                version=adapter.version,
                provenance=dict(adapter.provenance),
                staging_dir=staging_dir,
                filename=filename,
                descriptor=executable_fd,
            )
            provisional.remove()
