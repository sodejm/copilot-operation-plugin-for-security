"""Bounded subprocess collection for the isolated worker."""

from __future__ import annotations

import ctypes
import math
import os
import resource
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BoundedProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    timed_out: bool
    output_limit_exceeded: bool

    @property
    def captured_bytes(self) -> int:
        return len(self.stdout) + len(self.stderr)


@dataclass(frozen=True)
class ProcessResourceLimits:
    """Kernel-enforced limits applied before an untrusted tool starts."""

    address_space_bytes: int
    process_count: int
    cpu_seconds: float
    file_size_bytes: int
    open_files: int = 64

    def __post_init__(self) -> None:
        if (
            min(
                self.address_space_bytes,
                self.process_count,
                self.cpu_seconds,
                self.file_size_bytes,
                self.open_files,
            )
            <= 0
        ):
            raise ValueError("process resource limits must be positive")


def _resource_preexec(limits: ProcessResourceLimits) -> None:
    """Install non-bypassable Linux limits in the child before exec."""

    def lower(which: int, value: int) -> None:
        _, hard = resource.getrlimit(which)
        bounded = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(which, (bounded, bounded))

    lower(resource.RLIMIT_AS, limits.address_space_bytes)
    lower(resource.RLIMIT_NPROC, limits.process_count)
    lower(resource.RLIMIT_CPU, max(1, math.ceil(limits.cpu_seconds)))
    lower(resource.RLIMIT_FSIZE, limits.file_size_bytes)
    lower(resource.RLIMIT_NOFILE, limits.open_files)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")


def _terminate_process_group(process: subprocess.Popen[bytes], process_group_id: int) -> None:
    """Terminate the dedicated group, including children after the leader exits.

    A process group ID remains allocated while it has live members, so using the
    ID saved immediately after ``Popen(start_new_session=True)`` avoids a PID
    reuse race while descendants still hold the captured pipes.
    """
    try:
        if os.name == "posix":
            os.killpg(process_group_id, signal.SIGKILL)
        else:  # pragma: no cover - execution is rejected on non-POSIX hosts
            process.kill()
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin reports EPERM when the group contains only an exited leader
        # that has not yet been reaped. Reap it, then distinguish a vanished
        # group from descendants that we still cannot terminate.
        if process.poll() is None:
            raise
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    pass_fds: tuple[int, ...] = (),
    resource_limits: ProcessResourceLimits | None = None,
) -> BoundedProcessResult:
    """Run ``command`` while bounding retained stdout and stderr bytes.

    The aggregate limit is applied to raw bytes as pipes are drained.  Timeout
    and overflow terminate the whole process group, then drain/discard any
    remaining bytes so retained memory never exceeds the approved budget.  A
    timeout or overflow suppresses every retained byte: an arbitrary prefix may
    end in the middle of a credential and therefore cannot be redacted safely.
    """
    if os.name != "posix":
        raise RuntimeError("bounded executable collection requires POSIX process-group support")
    if max_output_bytes < 0:
        raise ValueError("max_output_bytes must be non-negative")
    if resource_limits is not None and not __import__("sys").platform.startswith("linux"):
        raise RuntimeError("kernel resource enforcement is supported only on Linux")

    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        env=dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        pass_fds=pass_fds,
        preexec_fn=(lambda: _resource_preexec(resource_limits)) if resource_limits is not None else None,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    process_group_id = process.pid

    streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
    selector: selectors.BaseSelector | None = None
    completed = False
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    overflow = False
    terminated = False
    drain_deadline: float | None = None

    try:
        selector = selectors.DefaultSelector()
        for stream, name in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if not terminated and remaining_time <= 0:
                timed_out = True
                terminated = True
                _terminate_process_group(process, process_group_id)
                drain_deadline = time.monotonic() + 0.5

            if drain_deadline is not None and time.monotonic() >= drain_deadline:
                # A hostile descendant can keep a duplicated pipe descriptor
                # open even after termination. Closing our read ends keeps this
                # collection path bounded.
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                break

            events = selector.select(timeout=0.05 if terminated else min(0.05, max(0.0, remaining_time)))
            if not events and process.poll() is not None:
                # Pipes will become readable at EOF; keep one short iteration to
                # drain kernel buffers before closing them.
                events = selector.select(timeout=0.05)

            for key, _ in events:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue

                retained = len(captured["stdout"]) + len(captured["stderr"])
                available = max(0, max_output_bytes - retained)
                if available:
                    captured[key.data].extend(chunk[:available])
                if len(chunk) > available and not overflow:
                    overflow = True
                    if not terminated:
                        terminated = True
                        _terminate_process_group(process, process_group_id)
                        drain_deadline = time.monotonic() + 0.5

        if process.poll() is None:
            _terminate_process_group(process, process_group_id)
        returncode = process.wait(timeout=2)
        completed = True
    finally:
        if not completed:
            # Setup and collection failures happen after dispatch. Reap the
            # leader and terminate descendants even when the leader has exited.
            _terminate_process_group(process, process_group_id)
        if selector is not None:
            selector.close()
        for stream, _ in streams:
            if not stream.closed:
                stream.close()
        if not completed:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                _terminate_process_group(process, process_group_id)
                process.wait(timeout=2)

    stdout = b"" if timed_out or overflow else bytes(captured["stdout"])
    stderr = b"" if timed_out or overflow else bytes(captured["stderr"])
    return BoundedProcessResult(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        timed_out=timed_out,
        output_limit_exceeded=overflow,
    )
