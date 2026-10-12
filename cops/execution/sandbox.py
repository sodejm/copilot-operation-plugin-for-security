"""Linux production sandbox for execution adapter processes."""

from __future__ import annotations

import json
import os
import re
import select
import socket
import stat
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cops.evidence.canonical import digest, utc_now

from .filesystem import SecureDirectoryError, open_directory_no_symlinks, same_directory_identity
from .process import BoundedProcessResult, ProcessResourceLimits, run_bounded_process


class SandboxReadinessError(RuntimeError):
    """A required operating-system execution boundary is unavailable."""


class OfflineIsolationViolation(SandboxReadinessError):
    """A started offline process did not have the approved isolation boundary."""


class ExecutionSandbox(Protocol):
    def assert_ready(self, worker_identity: str, *, cwd: Path, expected_workspace_fd: int | None = None) -> None: ...

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
        expected_workspace_fd: int | None = None,
        expected_isolation_digest: str | None = None,
        isolation_observer: Callable[[dict[str, Any]], None] | None = None,
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
    prlimit_path: Path = Path("/usr/bin/prlimit")
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
        if not self.prlimit_path.is_absolute():
            raise SandboxReadinessError("prlimit path must be absolute")
        self.resources.as_process_limits()

    @staticmethod
    def _validate_executable_ancestors(path: Path, name: str) -> None:
        current = Path(path.anchor)
        for component in path.parts[1:-1]:
            current /= component
            try:
                info = os.lstat(current)
            except OSError as err:
                raise SandboxReadinessError(f"{name} installation path is unavailable") from err
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise SandboxReadinessError(f"{name} installation ancestors must be root-owned and non-writable")

    @contextmanager
    def _held_root_executable(self, path: Path, name: str) -> Iterator[int]:
        self._validate_executable_ancestors(path, name)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as err:
            raise SandboxReadinessError(f"{name} is unavailable") from err
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                raise SandboxReadinessError(f"{name} must be a root-owned regular file")
            if info.st_mode & 0o022 or info.st_mode & 0o111 == 0:
                raise SandboxReadinessError(f"{name} permissions are unsafe")
            yield descriptor
        finally:
            os.close(descriptor)

    @contextmanager
    def _held_bubblewrap(self) -> Iterator[int]:
        with self._held_root_executable(self.bubblewrap_path, "bubblewrap") as descriptor:
            yield descriptor

    @contextmanager
    def _held_prlimit(self) -> Iterator[int]:
        with self._held_root_executable(self.prlimit_path, "prlimit") as descriptor:
            yield descriptor

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
    @contextmanager
    def _environment_arguments(sandbox_env: Mapping[str, str]) -> Iterator[int]:
        """Pass environment values to bubblewrap through an inherited memory FD."""
        try:
            descriptor = os.memfd_create("cops-bwrap-args", flags=getattr(os, "MFD_CLOEXEC", 1))
        except (AttributeError, OSError):
            raise SandboxReadinessError("private bubblewrap argument descriptor is unavailable") from None
        try:
            try:
                arguments = (
                    b"\0".join(
                        part.encode("utf-8")
                        for key, value in sorted(sandbox_env.items())
                        for part in ("--setenv", key, value)
                    )
                    + b"\0"
                )
            except UnicodeEncodeError:
                raise SandboxReadinessError("sandbox environment cannot be encoded") from None
            try:
                pending = memoryview(arguments)
                while pending:
                    written = os.write(descriptor, pending)
                    if written <= 0:
                        raise OSError("short write to private bubblewrap argument descriptor")
                    pending = pending[written:]
                os.lseek(descriptor, 0, os.SEEK_SET)
            except OSError:
                raise SandboxReadinessError("private bubblewrap arguments could not be prepared") from None
            yield descriptor
        finally:
            os.close(descriptor)

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

    def assert_ready(self, worker_identity: str, *, cwd: Path, expected_workspace_fd: int | None = None) -> None:
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
                expected_workspace_fd=expected_workspace_fd,
            )
        finally:
            os.close(true_fd)
        if probe.timed_out or probe.output_limit_exceeded or probe.returncode != 0:
            diagnostic = probe.stderr.decode("utf-8", errors="replace").strip()[:512]
            detail = diagnostic or f"exit status {probe.returncode}"
            raise SandboxReadinessError(f"bubblewrap namespace readiness probe failed: {detail}")

    def observe_offline_isolation(self, *, cwd: Path, expected_workspace_fd: int) -> dict[str, Any]:
        """Observe a gated fresh sandbox before approval consumption."""
        observations: list[dict[str, Any]] = []
        with self._held_root_executable(Path("/usr/bin/true"), "offline isolation probe") as executable_fd:
            result = self.run(
                [f"/proc/self/fd/{executable_fd}"],
                cwd=cwd,
                env={},
                timeout_seconds=5.0,
                max_output_bytes=4096,
                pass_fds=(executable_fd,),
                expected_workspace_fd=expected_workspace_fd,
                isolation_observer=observations.append,
            )
        if result.timed_out or result.output_limit_exceeded or result.returncode != 0 or len(observations) != 1:
            raise SandboxReadinessError("offline isolation observation failed")
        return observations[0]

    @staticmethod
    def _read_proc_lines(path: Path) -> list[str]:
        try:
            with path.open("rb") as stream:
                content = stream.read(65_537)
        except OSError as err:
            raise SandboxReadinessError("offline sandbox process observation is unavailable") from err
        if len(content) > 65_536:
            raise SandboxReadinessError("offline sandbox process observation exceeds its limit")
        try:
            return content.decode("ascii").splitlines()
        except UnicodeDecodeError as err:
            raise SandboxReadinessError("offline sandbox process observation is invalid") from err

    @classmethod
    def _measure_network_boundary(cls, child_pid: int) -> dict[str, Any]:
        proc = Path("/proc") / str(child_pid)
        try:
            separate = os.readlink(proc / "ns/net") != os.readlink("/proc/self/ns/net")
            socket_fds = 0
            for fd in (proc / "fd").iterdir():
                try:
                    socket_fds += os.readlink(fd).startswith("socket:[")
                except FileNotFoundError:
                    # The metadata descriptor may close while /proc is listed.
                    continue
        except OSError as err:
            raise SandboxReadinessError("offline sandbox process observation is unavailable") from err
        interfaces = sorted(
            line.split(":", 1)[0].strip() for line in cls._read_proc_lines(proc / "net/dev")[2:] if ":" in line
        )
        routes = [line.split()[0] for line in cls._read_proc_lines(proc / "net/route")[1:] if line.split()]
        ipv6_routes = [line.split()[-1] for line in cls._read_proc_lines(proc / "net/ipv6_route") if line.split()]
        measured = {
            "interfaces": interfaces,
            "routes": routes,
            "ipv6_routes": ipv6_routes,
            "socket_fds": socket_fds,
            "separate_network_namespace": separate,
        }
        return measured

    @staticmethod
    def _offline_network_boundary_restricted(measured: Mapping[str, Any]) -> bool:
        return (
            measured["separate_network_namespace"] is True
            and measured["interfaces"] == ["lo"]
            and all(route == "lo" for route in measured["routes"])
            and all(route == "lo" for route in measured["ipv6_routes"])
            and measured["socket_fds"] == 0
        )

    @classmethod
    def _authorize_offline_observation(
        cls,
        observation: dict[str, Any],
        expected_digest: str | None,
        observer: Callable[[dict[str, Any]], None] | None,
    ) -> None:
        # Record the actual blocked child before denying release. The worker's
        # result can then distinguish a rejected observation from no observation.
        if observer is not None:
            observer(observation)
        if not cls._offline_network_boundary_restricted(observation["measured"]):
            raise OfflineIsolationViolation("offline sandbox process has a network channel")
        if expected_digest is not None and observation["digest"] != expected_digest:
            raise OfflineIsolationViolation("offline sandbox process differs from approved isolation")

    @classmethod
    def _observe_blocked_child(cls, info_fd: int, deadline: float) -> dict[str, Any]:
        os.set_blocking(info_fd, False)
        content = bytearray()
        while time.monotonic() < deadline:
            readable, _, _ = select.select([info_fd], [], [], max(0.0, min(0.05, deadline - time.monotonic())))
            if not readable:
                continue
            chunk = os.read(info_fd, 4096)
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > 4096:
                raise SandboxReadinessError("offline sandbox process metadata exceeds its limit")
            try:
                metadata = json.loads(content)
            except (ValueError, UnicodeDecodeError):
                continue
            child_pid = metadata.get("child-pid") if isinstance(metadata, dict) else None
            if type(child_pid) is not int or child_pid <= 0:
                raise SandboxReadinessError("offline sandbox process metadata is invalid")
            measured = cls._measure_network_boundary(child_pid)
            return {
                "digest": digest(measured),
                "observed_at": utc_now(),
                "observation_scope": "pre_exec_actual_sandbox",
                "measured": measured,
            }
        raise SandboxReadinessError("offline sandbox process metadata is unavailable")

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
        expected_workspace_fd: int | None = None,
        expected_isolation_digest: str | None = None,
        isolation_observer: Callable[[dict[str, Any]], None] | None = None,
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
            if expected_workspace_fd is not None and not same_directory_identity(workspace_fd, expected_workspace_fd):
                raise SandboxReadinessError("sandbox workspace changed after preflight")
            with self._held_bubblewrap() as bubblewrap_fd, self._held_prlimit() as prlimit_fd:
                # RLIMIT_NPROC counts the host account's existing tasks. Applying it
                # before bwrap creates its namespaces can prevent isolation itself
                # from starting on a shared runner. Install it after isolation and
                # immediately before the untrusted tool instead.
                import resource

                _, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
                process_limit = self.resources.process_count
                if hard_limit != resource.RLIM_INFINITY:
                    process_limit = min(process_limit, hard_limit)
                if process_limit <= 0:
                    raise SandboxReadinessError("worker process limit is unavailable")
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
                    "--ro-bind",
                    f"/proc/self/fd/{prlimit_fd}",
                    "/cops/limit",
                    "--chdir",
                    "/work",
                ]
                with self._environment_arguments(sandbox_env) as argument_fd:
                    offline_gate = expected_isolation_digest is not None or isolation_observer is not None
                    info_read = info_write = gate_read = gate_write = -1
                    if offline_gate:
                        info_read, info_write = os.pipe2(os.O_CLOEXEC)
                        try:
                            gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
                        except OSError:
                            os.close(info_read)
                            os.close(info_write)
                            raise
                        wrapped.extend(("--info-fd", str(info_write), "--block-fd", str(gate_read)))
                    wrapped.extend(("--args", str(argument_fd)))
                    wrapped.extend(
                        (
                            "--",
                            "/cops/limit",
                            f"--nproc={process_limit}:{process_limit}",
                            "--",
                            "/cops/tool",
                            *command[1:],
                        )
                    )

                    def release_observed_child(_process: Any, deadline: float) -> None:
                        nonlocal info_write, gate_read, gate_write
                        os.close(info_write)
                        info_write = -1
                        os.close(gate_read)
                        gate_read = -1
                        observation = self._observe_blocked_child(info_read, deadline)
                        self._authorize_offline_observation(observation, expected_isolation_digest, isolation_observer)
                        os.write(gate_write, b"1")
                        os.close(gate_write)
                        gate_write = -1

                    try:
                        return run_bounded_process(
                            wrapped,
                            cwd=Path("/"),
                            env={},
                            timeout_seconds=timeout_seconds,
                            max_output_bytes=max_output_bytes,
                            pass_fds=(
                                bubblewrap_fd,
                                prlimit_fd,
                                workspace_fd,
                                executable_fd,
                                argument_fd,
                                *capability_fds,
                                *((info_write, gate_read) if offline_gate else ()),
                            ),
                            resource_limits=self.resources.as_process_limits(),
                            defer_process_limit=True,
                            on_started=release_observed_child if offline_gate else None,
                        )
                    finally:
                        for descriptor in (info_read, info_write, gate_read, gate_write):
                            if descriptor >= 0:
                                os.close(descriptor)
        finally:
            os.close(workspace_fd)
