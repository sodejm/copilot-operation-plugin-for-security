"""Strict, bounded SSH transport for one remote isolated-worker request."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from cops.execution.filesystem import SecureDirectoryError, open_directory_no_symlinks
from cops.execution.supervisor_attestation import (
    SupervisorAttestationError,
    load_attestation_key,
    validate_attestation_key_id,
)

SSH_PROTOCOL = "cops.remote-worker/v1"
SSH_ENDPOINT_INVENTORY_SCHEMA = "cops.ssh-remote-endpoint-inventory/v1"

_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_USERNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_HOST_KEY_ALGORITHMS = frozenset(
    {
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "ssh-ed25519",
    }
)
_MAX_PIN_BYTES = 16 * 1024
_MAX_INVENTORY_BYTES = 64 * 1024
_READ_CHUNK = 64 * 1024


class SSHTransportError(RuntimeError):
    """The remote exchange could not be authenticated or completed safely."""


@dataclass(frozen=True)
class SSHRemoteEndpoint:
    """Pinned configuration for one expected remote worker."""

    host: str
    port: int
    username: str
    worker_id: str
    known_hosts_path: Path
    remote_command: tuple[str, ...]
    attestation_key_id: str = ""
    attestation_key: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        _validate_host(self.host)
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65_535:
            raise ValueError("SSH port must be an integer from 1 through 65535")
        if not isinstance(self.username, str) or _USERNAME.fullmatch(self.username) is None:
            raise ValueError("SSH username is invalid")
        _validate_identity(self.worker_id, "worker identity")
        if not isinstance(self.known_hosts_path, Path):
            raise TypeError("known_hosts_path must be a pathlib.Path")
        if not self.known_hosts_path.is_absolute():
            raise ValueError("known_hosts_path must be absolute")
        if not isinstance(self.remote_command, tuple) or not self.remote_command:
            raise ValueError("remote_command must be a non-empty tuple")
        for argument in self.remote_command:
            if (
                not isinstance(argument, str)
                or not argument
                or len(argument) > 4096
                or any(character in argument for character in ("\x00", "\r", "\n"))
            ):
                raise ValueError("remote command contains an invalid argument")
        if bool(self.attestation_key_id) != bool(self.attestation_key):
            raise ValueError("supervisor attestation key ID and key must be configured together")
        if self.attestation_key_id:
            try:
                validate_attestation_key_id(self.attestation_key_id)
            except SupervisorAttestationError as err:
                raise ValueError("supervisor attestation key ID is invalid") from err
            if not isinstance(self.attestation_key, bytes) or len(self.attestation_key) != 32:
                raise ValueError("supervisor attestation key must contain 32 bytes")


@dataclass(frozen=True)
class SSHTransportLimits:
    """Byte and elapsed-time limits for one request/response exchange."""

    timeout_seconds: float = 30.0
    max_request_bytes: int = 64 * 1024
    max_response_bytes: int = 1024 * 1024
    max_diagnostic_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("SSH timeout must be positive")
        for name in ("max_request_bytes", "max_response_bytes", "max_diagnostic_bytes"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class SSHRemoteResponse:
    """An authenticated response from the configured host and worker."""

    request_id: str
    host: str
    worker_id: str
    payload: Any


@dataclass(frozen=True)
class SSHRemoteEndpointInventory:
    """Owner-provisioned mapping from approved worker identities to SSH endpoints."""

    schema_version: str
    endpoints: Mapping[str, SSHRemoteEndpoint]
    _file_verified: bool = field(default=False, init=False, repr=False, compare=False)

    SCHEMA_VERSION = SSH_ENDPOINT_INVENTORY_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "endpoints", MappingProxyType(dict(self.endpoints)))

    @classmethod
    def from_file(cls, path: Path | str) -> SSHRemoteEndpointInventory:
        """Load an exact-schema endpoint inventory through protected POSIX file access."""
        _require_posix_controls()
        source = Path(path)
        if not source.is_absolute() or source.name in ("", ".", ".."):
            raise SSHTransportError("SSH endpoint inventory path must be absolute")

        parent_descriptor = -1
        descriptor = -1
        try:
            parent_descriptor = open_directory_no_symlinks(source.parent)
            descriptor = os.open(
                source.name,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_descriptor,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise SSHTransportError("SSH endpoint inventory must be an owner-only regular file")
            if metadata.st_size > _MAX_INVENTORY_BYTES:
                raise SSHTransportError("SSH endpoint inventory exceeds the configured byte limit")
            raw = _read_bounded(
                descriptor,
                _MAX_INVENTORY_BYTES,
                overflow_message="SSH endpoint inventory exceeds the configured byte limit",
            )
        except SSHTransportError:
            raise
        except (OSError, SecureDirectoryError) as err:
            raise SSHTransportError("SSH endpoint inventory cannot be opened securely") from err
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)

        document = _decode_endpoint_inventory(raw)
        expected_fields = {"schema_version", "workers"}
        if not isinstance(document, dict) or set(document) != expected_fields:
            raise SSHTransportError("SSH endpoint inventory fields do not match the required schema")
        if document["schema_version"] != cls.SCHEMA_VERSION:
            raise SSHTransportError("unsupported SSH endpoint inventory schema version")
        workers = document["workers"]
        if not isinstance(workers, list) or not workers:
            raise SSHTransportError("SSH endpoint inventory workers must be a non-empty list")

        endpoints: dict[str, SSHRemoteEndpoint] = {}
        entry_fields = {
            "attestation_key_id",
            "attestation_key_path",
            "host",
            "known_hosts_path",
            "port",
            "remote_command",
            "username",
            "worker_id",
        }
        for entry in workers:
            if not isinstance(entry, dict) or set(entry) != entry_fields:
                raise SSHTransportError("SSH endpoint inventory worker fields do not match the required schema")
            worker_id = entry["worker_id"]
            if not isinstance(worker_id, str):
                raise SSHTransportError("SSH endpoint inventory worker identity is invalid")
            try:
                _validate_identity(worker_id, "worker identity")
            except ValueError as err:
                raise SSHTransportError("SSH endpoint inventory worker identity is invalid") from err
            if worker_id in endpoints:
                raise SSHTransportError("SSH endpoint inventory contains a duplicate worker identity")

            remote_command = entry["remote_command"]
            if not isinstance(remote_command, list):
                raise SSHTransportError("SSH endpoint inventory remote command must be a non-empty string list")
            known_hosts_path = entry["known_hosts_path"]
            attestation_key_path = entry["attestation_key_path"]
            if not isinstance(known_hosts_path, str) or not isinstance(attestation_key_path, str):
                raise SSHTransportError("SSH endpoint inventory known-hosts path is invalid")
            try:
                attestation_key = load_attestation_key(Path(attestation_key_path))
                endpoint = SSHRemoteEndpoint(
                    host=entry["host"],
                    port=entry["port"],
                    username=entry["username"],
                    worker_id=worker_id,
                    known_hosts_path=Path(known_hosts_path),
                    remote_command=tuple(remote_command),
                    attestation_key_id=entry["attestation_key_id"],
                    attestation_key=attestation_key,
                )
            except (TypeError, ValueError, SupervisorAttestationError) as err:
                raise SSHTransportError("SSH endpoint inventory contains an invalid worker endpoint") from err
            endpoints[worker_id] = endpoint

        inventory = cls(schema_version=cls.SCHEMA_VERSION, endpoints=endpoints)
        object.__setattr__(inventory, "_file_verified", True)
        return inventory

    @property
    def is_verified(self) -> bool:
        """Whether the inventory passed the protected file loader."""
        return self._file_verified

    def resolve(self, worker_id: str) -> SSHRemoteEndpoint:
        """Resolve one exact worker identity without accepting caller endpoint fields."""
        if not self.is_verified:
            raise SSHTransportError("a verified owner-provisioned SSH endpoint inventory is required")
        try:
            _validate_identity(worker_id, "worker identity")
        except ValueError as err:
            raise SSHTransportError("SSH worker identity is invalid") from err
        try:
            return self.endpoints[worker_id]
        except KeyError as err:
            raise SSHTransportError("SSH worker identity is not present in the trusted inventory") from err


class SSHRemoteDispatcher:
    """Resolve an approved worker identity and dispatch through its trusted endpoint."""

    def __init__(
        self,
        inventory: SSHRemoteEndpointInventory,
        *,
        limits: SSHTransportLimits | None = None,
        ssh_executable: Path = Path("/usr/bin/ssh"),
    ) -> None:
        if not isinstance(inventory, SSHRemoteEndpointInventory) or not inventory.is_verified:
            raise SSHTransportError("a verified owner-provisioned SSH endpoint inventory is required")
        self._inventory = inventory
        self._limits = limits
        self._ssh_executable = ssh_executable

    def request(self, worker_id: str, payload: Mapping[str, object], *, request_id: str) -> SSHRemoteResponse:
        """Dispatch one request using only the endpoint bound to ``worker_id``."""
        endpoint = self._inventory.resolve(worker_id)
        transport = SSHRemoteTransport(
            endpoint,
            limits=self._limits,
            ssh_executable=self._ssh_executable,
        )
        return transport.request(payload, request_id=request_id)


@dataclass(frozen=True)
class _CollectedExchange:
    stdout: bytes
    stderr: bytes
    returncode: int
    timed_out: bool
    response_limit_exceeded: bool
    diagnostic_limit_exceeded: bool


class SSHRemoteTransport:
    """Send one JSON request through a pinned OpenSSH connection."""

    def __init__(
        self,
        endpoint: SSHRemoteEndpoint,
        *,
        limits: SSHTransportLimits | None = None,
        ssh_executable: Path = Path("/usr/bin/ssh"),
    ) -> None:
        if not isinstance(endpoint, SSHRemoteEndpoint):
            raise TypeError("endpoint must be an SSHRemoteEndpoint")
        if not isinstance(ssh_executable, Path) or not ssh_executable.is_absolute():
            raise ValueError("ssh_executable must be an absolute pathlib.Path")
        self._endpoint = endpoint
        self._limits = limits or SSHTransportLimits()
        self._ssh_executable = ssh_executable

    def request(self, payload: Mapping[str, object], *, request_id: str) -> SSHRemoteResponse:
        """Exchange one bounded request and verify every response binding."""
        if not isinstance(payload, Mapping):
            raise TypeError("SSH request payload must be a mapping")
        _validate_identity(request_id, "request identifier")
        _require_posix_controls()
        deadline = time.monotonic() + float(self._limits.timeout_seconds)
        envelope = {
            "expected_host": self._endpoint.host,
            "expected_worker_id": self._endpoint.worker_id,
            "payload": dict(payload),
            "protocol": SSH_PROTOCOL,
            "request_id": request_id,
        }
        try:
            request_bytes = (
                json.dumps(envelope, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
            )
        except (TypeError, ValueError) as err:
            raise SSHTransportError("SSH request payload is not valid JSON") from err
        if len(request_bytes) > self._limits.max_request_bytes:
            raise SSHTransportError("SSH request exceeds the configured byte limit")

        executable_descriptor = -1
        executable_pass_fds: tuple[int, ...] = ()
        try:
            executable_descriptor, executable_metadata = _open_executable(self._ssh_executable)
            pin, host_key_algorithm = _load_exact_host_pin(self._endpoint)
            with tempfile.TemporaryDirectory(prefix="cops-ssh-") as temporary_directory:
                private_directory = Path(temporary_directory)
                os.chmod(private_directory, 0o700)
                if _path_is_immutable_to_current_user(self._ssh_executable, executable_metadata):
                    # Preserve platform-signed system binaries: the held descriptor and a
                    # non-writable file/parent chain make this path stable for this identity.
                    descriptor_launch_path = _descriptor_launch_path(executable_descriptor, executable_metadata)
                    if descriptor_launch_path is not None:
                        launch_executable = descriptor_launch_path
                        executable_pass_fds = (executable_descriptor,)
                    else:
                        launch_executable = self._ssh_executable
                else:
                    # A mutable executable can be renamed after opening, changing its
                    # ctime even when the held inode still contains the validated code.
                    # Launch a checked private copy instead of that mutable inode.
                    launch_executable = _stage_executable(
                        executable_descriptor,
                        executable_metadata,
                        private_directory,
                    )
                    os.close(executable_descriptor)
                    executable_descriptor = -1
                staged_pin = private_directory / "known_hosts"
                descriptor = os.open(
                    staged_pin,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                try:
                    _write_all(descriptor, pin)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SSHTransportError("SSH exchange exceeded the configured time limit")
                command = self._command(launch_executable, staged_pin, host_key_algorithm)
                result = _run_exchange(
                    command,
                    request_bytes=request_bytes,
                    cwd=private_directory,
                    timeout_seconds=remaining,
                    max_response_bytes=self._limits.max_response_bytes,
                    max_diagnostic_bytes=self._limits.max_diagnostic_bytes,
                    pass_fds=executable_pass_fds,
                )
                if executable_descriptor >= 0:
                    _verify_executable_unchanged(executable_descriptor, executable_metadata)
        except SSHTransportError:
            raise
        except OSError as err:
            raise SSHTransportError("SSH transport setup failed") from err
        finally:
            if executable_descriptor >= 0:
                os.close(executable_descriptor)

        if result.timed_out:
            raise SSHTransportError("SSH exchange exceeded the configured time limit")
        if result.response_limit_exceeded:
            raise SSHTransportError("SSH response exceeds the configured byte limit")
        if result.diagnostic_limit_exceeded:
            raise SSHTransportError("SSH diagnostics exceed the configured byte limit")
        if result.returncode != 0:
            raise SSHTransportError(f"SSH exchange failed with exit status {result.returncode}")
        return _decode_response(result.stdout, self._endpoint, request_id)

    def _command(self, staged_executable: Path, staged_pin: Path, host_key_algorithm: str) -> list[str]:
        options = (
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            f"UserKnownHostsFile={staged_pin}",
            "GlobalKnownHostsFile=/dev/null",
            "VerifyHostKeyDNS=no",
            "CheckHostIP=no",
            "UpdateHostKeys=no",
            "CanonicalizeHostname=no",
            "ProxyCommand=none",
            "ProxyJump=none",
            "PermitLocalCommand=no",
            "ClearAllForwardings=yes",
            "ExitOnForwardFailure=yes",
            "RequestTTY=no",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "GSSAPIAuthentication=no",
            "IdentitiesOnly=yes",
            f"HostKeyAlgorithms={host_key_algorithm}",
        )
        command = [os.fspath(staged_executable), "-F", "/dev/null"]
        for option in options:
            command.extend(("-o", option))
        command.extend(
            (
                "-p",
                str(self._endpoint.port),
                "-l",
                self._endpoint.username,
                "-T",
                "--",
                self._endpoint.host,
                shlex.join(self._endpoint.remote_command),
            )
        )
        return command


def _validate_host(host: str) -> None:
    if not isinstance(host, str) or not host or len(host) > 253 or host.endswith("."):
        raise ValueError("SSH host must be a canonical DNS name or IP address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if (
            re.fullmatch(r"[0-9.]+", host)
            or host != host.lower()
            or any(_HOST_LABEL.fullmatch(label) is None for label in host.split("."))
        ):
            raise ValueError("SSH host must be a canonical DNS name or IP address") from None
    else:
        if str(address) != host:
            raise ValueError("SSH host must use canonical IP address spelling")


def _validate_identity(value: str, label: str) -> None:
    if not isinstance(value, str) or _IDENTITY.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")


def _expected_known_host(endpoint: SSHRemoteEndpoint) -> str:
    return endpoint.host if endpoint.port == 22 else f"[{endpoint.host}]:{endpoint.port}"


def _load_exact_host_pin(endpoint: SSHRemoteEndpoint) -> tuple[bytes, str]:
    path = endpoint.known_hosts_path
    if path.name in ("", ".", ".."):
        raise SSHTransportError("SSH known-host pin is invalid")
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = open_directory_no_symlinks(path.parent)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise SSHTransportError("SSH known-host pin must be an owner-only regular file")
        if metadata.st_size > _MAX_PIN_BYTES:
            raise SSHTransportError("SSH known-host pin exceeds the configured byte limit")
        raw = _read_bounded(
            descriptor,
            _MAX_PIN_BYTES,
            overflow_message="SSH known-host pin exceeds the configured byte limit",
        )
    except SSHTransportError:
        raise
    except (OSError, SecureDirectoryError) as err:
        raise SSHTransportError("SSH known-host pin cannot be opened securely") from err
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)

    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as err:
        raise SSHTransportError("SSH known-host pin is malformed") from err
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1 or lines[0].lstrip().startswith(("#", "@")):
        raise SSHTransportError("SSH known-host pin must contain exactly one literal entry")
    fields = lines[0].split()
    if len(fields) != 3:
        raise SSHTransportError("SSH known-host pin is malformed")
    host_field, algorithm, encoded_key = fields
    if (
        host_field != _expected_known_host(endpoint)
        or any(marker in host_field for marker in (",", "*", "?", "|"))
        or algorithm not in _HOST_KEY_ALGORITHMS
    ):
        raise SSHTransportError("SSH known-host pin does not match the configured endpoint")
    try:
        decoded_key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError) as err:
        raise SSHTransportError("SSH known-host pin is malformed") from err
    if not decoded_key:
        raise SSHTransportError("SSH known-host pin is malformed")
    return f"{host_field} {algorithm} {encoded_key}\n".encode("ascii"), algorithm


def _open_executable(path: Path) -> tuple[int, os.stat_result]:
    if path.name in ("", ".", ".."):
        raise SSHTransportError("SSH executable cannot be opened securely")
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = open_directory_no_symlinks(path.parent)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
            raise SSHTransportError("SSH executable must be an executable regular file")
        opened_descriptor = descriptor
        descriptor = -1
        return opened_descriptor, metadata
    except SSHTransportError:
        raise
    except (OSError, SecureDirectoryError) as err:
        raise SSHTransportError("SSH executable cannot be opened securely") from err
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _stage_executable(
    source_descriptor: int,
    expected_metadata: os.stat_result,
    private_directory: Path,
) -> Path:
    staged_path = private_directory / "ssh-executable"
    staged_descriptor = -1
    copied_bytes = 0
    try:
        staged_descriptor = os.open(
            staged_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o500,
        )
        os.fchmod(staged_descriptor, 0o500)
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        while copied_bytes <= expected_metadata.st_size:
            chunk = os.read(
                source_descriptor,
                min(_READ_CHUNK, expected_metadata.st_size + 1 - copied_bytes),
            )
            if not chunk:
                break
            _write_all(staged_descriptor, chunk)
            copied_bytes += len(chunk)
        current_metadata = os.fstat(source_descriptor)
        if copied_bytes != expected_metadata.st_size or _executable_identity(current_metadata) != _executable_identity(
            expected_metadata
        ):
            raise SSHTransportError("SSH executable changed while being staged")
        os.fsync(staged_descriptor)
    except SSHTransportError:
        raise
    except OSError as err:
        raise SSHTransportError("SSH executable cannot be staged securely") from err
    finally:
        if staged_descriptor >= 0:
            os.close(staged_descriptor)
    return staged_path


def _path_is_immutable_to_current_user(path: Path, expected_metadata: os.stat_result) -> bool:
    if not hasattr(os, "geteuid") or os.geteuid() == 0 or expected_metadata.st_uid == os.geteuid():
        return False
    try:
        current_metadata = path.lstat()
        if _executable_identity(current_metadata) != _executable_identity(expected_metadata):
            return False
        if current_metadata.st_mode & 0o022 or os.access(path, os.W_OK, effective_ids=True):
            return False
        current = path.parent
        while True:
            metadata = current.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_mode & 0o022
                or metadata.st_uid == os.geteuid()
                or os.access(current, os.W_OK, effective_ids=True)
            ):
                return False
            if current == current.parent:
                return True
            current = current.parent
    except (NotImplementedError, OSError):
        return False


def _descriptor_launch_path(descriptor: int, expected_metadata: os.stat_result) -> Path | None:
    descriptor_path = Path("/proc/self/fd") / str(descriptor)
    try:
        current_metadata = descriptor_path.stat()
    except OSError:
        return None
    if _executable_identity(current_metadata) != _executable_identity(expected_metadata):
        return None
    return descriptor_path


def _verify_executable_unchanged(descriptor: int, expected_metadata: os.stat_result) -> None:
    try:
        current_metadata = os.fstat(descriptor)
    except OSError as err:
        raise SSHTransportError("SSH executable could not be revalidated") from err
    if _executable_identity(current_metadata) != _executable_identity(expected_metadata):
        raise SSHTransportError("SSH executable changed during launch")


def _executable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        offset += os.write(descriptor, content[offset:])


def _read_bounded(descriptor: int, limit: int, *, overflow_message: str) -> bytes:
    chunks = bytearray()
    while True:
        chunk = os.read(descriptor, min(_READ_CHUNK, limit + 1 - len(chunks)))
        if not chunk:
            return bytes(chunks)
        chunks.extend(chunk)
        if len(chunks) > limit:
            raise SSHTransportError(overflow_message)


def _terminate_process_group(process: subprocess.Popen[bytes], process_group_id: int) -> None:
    try:
        os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # A leader can exit while descendants remain in its process group.
        # Ignore the race only when the entire group is confirmed absent.
        if process.poll() is None:
            raise
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return
        raise


def _run_exchange(
    command: Sequence[str],
    *,
    request_bytes: bytes,
    cwd: Path,
    timeout_seconds: float,
    max_response_bytes: int,
    max_diagnostic_bytes: int,
    pass_fds: tuple[int, ...] = (),
) -> _CollectedExchange:
    if os.name != "posix":
        raise SSHTransportError("SSH transport requires POSIX process-group support")
    with tempfile.TemporaryFile() as request_file:
        request_file.write(request_bytes)
        request_file.seek(0)
        try:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                stdin=request_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=pass_fds,
                start_new_session=True,
            )
        except OSError as err:
            raise SSHTransportError("SSH transport launch failed") from err

        assert process.stdout is not None
        assert process.stderr is not None
        process_group_id = process.pid
        streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
        limits = {"stdout": max_response_bytes, "stderr": max_diagnostic_bytes}
        retained = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = {"stdout": False, "stderr": False}
        selector: selectors.BaseSelector | None = None
        completed = False
        timed_out = False
        terminated = False
        drain_deadline: float | None = None
        deadline = time.monotonic() + timeout_seconds
        try:
            selector = selectors.DefaultSelector()
            for stream, name in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if not terminated and remaining <= 0:
                    timed_out = True
                    terminated = True
                    _terminate_process_group(process, process_group_id)
                    drain_deadline = time.monotonic() + 0.5
                if drain_deadline is not None and time.monotonic() >= drain_deadline:
                    for key in list(selector.get_map().values()):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    break
                wait = 0.05 if terminated else min(0.05, max(0.0, remaining))
                events = selector.select(wait)
                for key, _ in events:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), _READ_CHUNK)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    name = key.data
                    available = max(0, limits[name] - len(retained[name]))
                    if available:
                        retained[name].extend(chunk[:available])
                    if len(chunk) > available:
                        overflow[name] = True
                        if not terminated:
                            terminated = True
                            _terminate_process_group(process, process_group_id)
                            drain_deadline = time.monotonic() + 0.5
            if terminated:
                returncode = process.wait(timeout=2)
            else:
                # EOF can arrive just before SSH exits. Give the leader a bounded
                # chance to exit naturally before treating it as stuck.
                grace = min(0.25, max(0.0, deadline - time.monotonic()))
                try:
                    returncode = process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    _terminate_process_group(process, process_group_id)
                    returncode = process.wait(timeout=2)
            completed = True
        finally:
            if not completed:
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

    suppress_output = timed_out or any(overflow.values())
    return _CollectedExchange(
        stdout=b"" if suppress_output else bytes(retained["stdout"]),
        stderr=b"" if suppress_output else bytes(retained["stderr"]),
        returncode=returncode,
        timed_out=timed_out,
        response_limit_exceeded=overflow["stdout"],
        diagnostic_limit_exceeded=overflow["stderr"],
    )


def _decode_response(stdout: bytes, endpoint: SSHRemoteEndpoint, request_id: str) -> SSHRemoteResponse:
    try:
        decoded = stdout.decode("utf-8")
        response = json.loads(
            decoded,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise SSHTransportError("SSH response is not valid JSON") from err
    expected_fields = {"protocol", "request_id", "host", "worker_id", "payload"}
    if not isinstance(response, dict) or set(response) != expected_fields:
        raise SSHTransportError("SSH response envelope is malformed")
    if response["protocol"] != SSH_PROTOCOL:
        raise SSHTransportError("SSH response protocol does not match the request")
    if response["request_id"] != request_id:
        raise SSHTransportError("SSH response request identifier does not match")
    if response["host"] != endpoint.host:
        raise SSHTransportError("SSH response host identity does not match")
    if response["worker_id"] != endpoint.worker_id:
        raise SSHTransportError("SSH response worker identity does not match")
    return SSHRemoteResponse(
        request_id=request_id,
        host=endpoint.host,
        worker_id=endpoint.worker_id,
        payload=response["payload"],
    )


def _decode_endpoint_inventory(raw: bytes) -> object:
    try:
        decoded = raw.decode("utf-8")
        return json.loads(
            decoded,
            object_pairs_hook=_strict_inventory_json_object,
            parse_constant=_reject_inventory_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise SSHTransportError("SSH endpoint inventory is not valid JSON") from err


def _strict_inventory_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SSHTransportError("SSH endpoint inventory is not valid JSON")
        value[key] = item
    return value


def _reject_inventory_json_constant(_value: str) -> object:
    raise SSHTransportError("SSH endpoint inventory is not valid JSON")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SSHTransportError("SSH response is not valid JSON")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> object:
    raise SSHTransportError("SSH response is not valid JSON")


def _require_posix_controls() -> None:
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
    if os.name != "posix" or any(not hasattr(os, name) for name in required_flags):
        raise SSHTransportError("SSH transport requires POSIX filesystem controls")
