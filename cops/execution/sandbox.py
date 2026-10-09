"""Linux production sandbox for execution adapter processes."""

from __future__ import annotations

import os
import re
import socket
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .filesystem import SecureDirectoryError, open_directory_no_symlinks
from .process import BoundedProcessResult, ProcessResourceLimits, run_bounded_process


class SandboxReadinessError(RuntimeError):
    """A required operating-system execution boundary is unavailable."""


class ExecutionSandbox(Protocol):
    def assert_ready(self, worker_identity: str, *, cwd: Path) -> None: ...

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
        pass_fds: tuple[int, ...] = (),
        operation_env: Mapping[str, str] | None = None,
        capability_fds: tuple[int, ...] = (),
    ) -> BoundedProcessResult: ...


@dataclass(frozen=True)
class SandboxResourcePolicy:
    address_space_bytes: int = 512 * 1024 * 1024
    process_count: int = 32
    cpu_seconds: float = 30.0
    file_size_bytes: int = 16 * 1024 * 1024
    open_files: int = 64

    def as_process_limits(self) -> ProcessResourceLimits:
        return ProcessResourceLimits(
            address_space_bytes=self.address_space_bytes,
            process_count=self.process_count,
            cpu_seconds=self.cpu_seconds,
            file_size_bytes=self.file_size_bytes,
            open_files=self.open_files,
        )


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_EGRESS_BROKER_FD_ENV = "COPS_EGRESS_BROKER_FD"


@dataclass(frozen=True)
class LinuxBubblewrapSandbox:
    """Run each adapter in a fresh bwrap namespace with kernel limits."""

    bubblewrap_path: Path = Path("/usr/bin/bwrap")
    worker_uid: int | None = None
    worker_gid: int | None = None
    resources: SandboxResourcePolicy = SandboxResourcePolicy()

    def _validate_host(self) -> None:
        if not sys.platform.startswith("linux") or os.name != "posix":
            raise SandboxReadinessError("production process isolation is supported only on Linux")
        actual_uid, actual_gid = os.geteuid(), os.getegid()
        expected_uid = actual_uid if self.worker_uid is None else self.worker_uid
        expected_gid = actual_gid if self.worker_gid is None else self.worker_gid
        if (expected_uid, expected_gid) != (actual_uid, actual_gid):
            raise SandboxReadinessError("configured sandbox UID/GID do not match the running worker")
        if actual_uid == 0:
            raise SandboxReadinessError("sandboxed worker must not run as root")
        if not self.bubblewrap_path.is_absolute():
            raise SandboxReadinessError("bubblewrap path must be absolute")
        self.resources.as_process_limits()

    def _validate_bubblewrap_ancestors(self) -> None:
        current = Path(self.bubblewrap_path.anchor)
        for component in self.bubblewrap_path.parts[1:-1]:
            current /= component
            try:
                info = os.lstat(current)
            except OSError as err:
                raise SandboxReadinessError("bubblewrap installation path is unavailable") from err
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise SandboxReadinessError("bubblewrap installation ancestors must be root-owned and non-writable")

    @contextmanager
    def _held_bubblewrap(self) -> Iterator[int]:
        self._validate_bubblewrap_ancestors()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.bubblewrap_path, flags)
        except OSError as err:
            raise SandboxReadinessError("bubblewrap is unavailable") from err
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                raise SandboxReadinessError("bubblewrap must be a root-owned regular file")
            if info.st_mode & 0o022 or info.st_mode & 0o111 == 0:
                raise SandboxReadinessError("bubblewrap permissions are unsafe")
            yield descriptor
        finally:
            os.close(descriptor)

    @staticmethod
    def _open_private_workspace(cwd: Path) -> int:
        try:
            descriptor = open_directory_no_symlinks(cwd)
        except SecureDirectoryError as err:
            raise SandboxReadinessError("sandbox workspace is unavailable or contains a symbolic link") from err
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            os.close(descriptor)
            raise SandboxReadinessError("sandbox workspace must be private to the worker account")
        return descriptor

    @staticmethod
    def _sandbox_environment(env: Mapping[str, str], operation_env: Mapping[str, str] | None) -> dict[str, str]:
        sandbox_env = {"PATH": "/usr/bin:/bin", "HOME": "/home/cops", "TMPDIR": "/tmp"}  # noqa: S108 - private sandbox tmpfs
        sandbox_env.update({key: value for key, value in env.items() if key in {"LANG", "LC_ALL", "TZ"}})
        for key, value in (operation_env or {}).items():
            if not isinstance(key, str) or _ENV_NAME.fullmatch(key) is None:
                raise SandboxReadinessError("operation environment contains an invalid variable name")
            if not isinstance(value, str) or "\x00" in value:
                raise SandboxReadinessError("operation environment contains an invalid value")
            sandbox_env[key] = value
        return sandbox_env

    @staticmethod
    def _validate_fds(
        executable_fd: int,
        capability_fds: tuple[int, ...],
        operation_env: Mapping[str, str] | None,
    ) -> None:
        descriptors = (executable_fd, *capability_fds)
        if any(not isinstance(fd, int) or fd < 0 for fd in descriptors) or len(set(descriptors)) != len(descriptors):
            raise SandboxReadinessError("sandbox capability descriptors must be distinct open file descriptors")
        try:
            for descriptor in descriptors:
                os.fstat(descriptor)
        except OSError as err:
            raise SandboxReadinessError("sandbox capability descriptor is not open") from err

        broker_value = (operation_env or {}).get(_EGRESS_BROKER_FD_ENV)
        if not capability_fds:
            if broker_value is not None:
                raise SandboxReadinessError("egress broker environment requires its capability descriptor")
            return
        if len(capability_fds) != 1 or broker_value != str(capability_fds[0]):
            raise SandboxReadinessError("sandbox accepts only the mapped egress broker capability descriptor")

        try:
            duplicate = os.dup(capability_fds[0])
            try:
                broker_socket = socket.socket(fileno=duplicate)
            except OSError:
                os.close(duplicate)
                raise
            try:
                if broker_socket.family != socket.AF_UNIX:
                    raise SandboxReadinessError("egress broker capability must be an AF_UNIX socket")
                if broker_socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
                    raise SandboxReadinessError("egress broker capability must be a stream socket")
                broker_socket.getpeername()
            finally:
                broker_socket.close()
        except SandboxReadinessError:
            raise
        except OSError as err:
            raise SandboxReadinessError("egress broker capability must be a connected AF_UNIX socket") from err

    @staticmethod
    def _base_command(bubblewrap_fd: int) -> list[str]:
        command = [
            f"/proc/self/fd/{bubblewrap_fd}",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
        ]
        for path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(path).exists():
                command.extend(("--ro-bind", path, path))
        command.extend(("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/run"))  # noqa: S108 - private tmpfs mount
        return command

    def assert_ready(self, worker_identity: str, *, cwd: Path) -> None:
        if not worker_identity.strip():
            raise SandboxReadinessError("worker identity must be non-empty")
        self._validate_host()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            true_fd = os.open("/usr/bin/true", flags)
        except OSError as err:
            raise SandboxReadinessError("sandbox readiness executable is unavailable") from err
        try:
            probe = self.run(
                [f"/proc/self/fd/{true_fd}"],
                cwd=cwd,
                env={},
                timeout_seconds=5.0,
                max_output_bytes=4096,
                pass_fds=(true_fd,),
            )
        finally:
            os.close(true_fd)
        if probe.timed_out or probe.output_limit_exceeded or probe.returncode != 0:
            diagnostic = probe.stderr.decode("utf-8", errors="replace").strip()[:512]
            detail = diagnostic or f"exit status {probe.returncode}"
            raise SandboxReadinessError(f"bubblewrap namespace readiness probe failed: {detail}")

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
        pass_fds: tuple[int, ...] = (),
        operation_env: Mapping[str, str] | None = None,
        capability_fds: tuple[int, ...] = (),
    ) -> BoundedProcessResult:
        self._validate_host()
        if not command or len(pass_fds) != 1:
            raise SandboxReadinessError("sandbox execution requires exactly one held executable descriptor")
        executable_fd = pass_fds[0]
        if command[0] != f"/proc/self/fd/{executable_fd}":
            raise SandboxReadinessError("sandbox command must use the held executable descriptor")
        self._validate_fds(executable_fd, capability_fds, operation_env)
        sandbox_env = self._sandbox_environment(env, operation_env)
        workspace_fd = self._open_private_workspace(cwd)
        try:
            with self._held_bubblewrap() as bubblewrap_fd:
                wrapped = [
                    *self._base_command(bubblewrap_fd),
                    "--bind",
                    f"/proc/self/fd/{workspace_fd}",
                    "/work",
                    "--dir",
                    "/cops",
                    "--ro-bind",
                    f"/proc/self/fd/{executable_fd}",
                    "/cops/tool",
                    "--chdir",
                    "/work",
                ]
                for key, value in sorted(sandbox_env.items()):
                    wrapped.extend(("--setenv", key, value))
                wrapped.extend(("--", "/cops/tool", *command[1:]))
                return run_bounded_process(
                    wrapped,
                    cwd=Path("/"),
                    env={},
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                    pass_fds=(bubblewrap_fd, workspace_fd, executable_fd, *capability_fds),
                    resource_limits=self.resources.as_process_limits(),
                )
        finally:
            os.close(workspace_fd)
