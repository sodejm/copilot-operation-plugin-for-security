"""Credential provider transport for the persistent execution supervisor."""

from __future__ import annotations

import json
import math
import os
import socket
import stat
import struct
import sys
import time
from pathlib import Path

from cops.execution.filesystem import open_directory_no_symlinks

PROTOCOL = "cops.credential-provider/v1"
MAX_REFERENCE_BYTES = 1024
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 1024 * 1024


class CredentialProviderTransportError(RuntimeError):
    """The credential provider request failed without exposing secret material."""


class UnixSocketCredentialProvider:
    """Resolve opaque credential references through a pinned local Unix peer."""

    def __init__(
        self,
        socket_path: Path | str,
        *,
        expected_provider_uid: int,
        expected_provider_gid: int,
        default_timeout_seconds: float = 5.0,
    ) -> None:
        path = Path(socket_path)
        if not path.is_absolute():
            raise ValueError("credential provider socket path must be absolute")
        if type(expected_provider_uid) is not int or expected_provider_uid < 1:
            raise ValueError("credential provider UID must be a non-root integer")
        if type(expected_provider_gid) is not int or expected_provider_gid < 1:
            raise ValueError("credential provider GID must be a non-root integer")
        if (
            not isinstance(default_timeout_seconds, (int, float))
            or isinstance(default_timeout_seconds, bool)
            or not math.isfinite(default_timeout_seconds)
            or default_timeout_seconds <= 0
        ):
            raise ValueError("credential provider timeout must be finite and positive")
        self._socket_path = path
        self._expected_provider_uid = expected_provider_uid
        self._expected_provider_gid = expected_provider_gid
        self._default_timeout_seconds = float(default_timeout_seconds)

    def resolve(
        self,
        reference: str,
        *,
        deadline: float | None = None,
        timeout: float | None = None,
    ) -> str:
        """Resolve one reference within one absolute monotonic deadline.

        ``deadline`` is preferred by the worker resolver. ``timeout`` is retained
        for direct callers and is converted to the same absolute budget.
        """
        if deadline is not None and timeout is not None:
            raise ValueError("credential provider accepts either deadline or timeout")
        if not isinstance(reference, str) or not reference or "\x00" in reference or "\n" in reference:
            raise ValueError("credential reference is invalid")
        if len(reference.encode("utf-8")) > MAX_REFERENCE_BYTES:
            raise ValueError("credential reference exceeds the byte limit")
        if deadline is None:
            duration = self._default_timeout_seconds if timeout is None else timeout
            if (
                not isinstance(duration, (int, float))
                or isinstance(duration, bool)
                or not math.isfinite(duration)
                or duration <= 0
            ):
                raise ValueError("credential provider timeout must be finite and positive")
            deadline = time.monotonic() + float(duration)
        elif not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or not math.isfinite(deadline):
            raise ValueError("credential provider deadline must be finite")

        self._validate_socket_path()
        request = (
            json.dumps(
                {"protocol": PROTOCOL, "reference": reference},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if len(request) > MAX_REQUEST_BYTES:
            raise ValueError("credential provider request exceeds the byte limit")

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                self._set_remaining_timeout(connection, deadline)
                connection.connect(str(self._socket_path))
                self._verify_peer(connection, deadline)
                self._set_remaining_timeout(connection, deadline)
                connection.sendall(request)
                connection.shutdown(socket.SHUT_WR)
                response = self._read_response(connection, deadline)
        except CredentialProviderTransportError:
            raise
        except (OSError, TimeoutError):
            raise CredentialProviderTransportError("credential provider transport failed") from None

        return self._parse_response(response, reference)

    def _validate_socket_path(self) -> None:
        if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
            raise CredentialProviderTransportError("credential provider requires Linux peer credentials")
        descriptor = -1
        try:
            descriptor = open_directory_no_symlinks(self._socket_path.parent)
            directory = os.fstat(descriptor)
            if not stat.S_ISDIR(directory.st_mode):
                raise CredentialProviderTransportError("credential provider socket directory is invalid")
            if directory.st_uid not in (0, self._expected_provider_uid) or directory.st_mode & 0o022:
                raise CredentialProviderTransportError("credential provider socket directory is untrusted")
            info = os.stat(self._socket_path.name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISSOCK(info.st_mode):
                raise CredentialProviderTransportError("credential provider endpoint is not a socket")
            if (info.st_uid, info.st_gid) != (
                self._expected_provider_uid,
                self._expected_provider_gid,
            ):
                raise CredentialProviderTransportError("credential provider socket ownership mismatch")
            if stat.S_IMODE(info.st_mode) & 0o007:
                raise CredentialProviderTransportError("credential provider socket permits other users")
        except CredentialProviderTransportError:
            raise
        except OSError:
            raise CredentialProviderTransportError("credential provider endpoint is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _verify_peer(self, connection: socket.socket, deadline: float) -> None:
        self._set_remaining_timeout(connection, deadline)
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, gid = struct.unpack("3i", raw)
        except (OSError, struct.error):
            raise CredentialProviderTransportError("credential provider peer identity is unavailable") from None
        if (uid, gid) != (self._expected_provider_uid, self._expected_provider_gid):
            raise CredentialProviderTransportError("credential provider peer identity mismatch")

    @staticmethod
    def _set_remaining_timeout(connection: socket.socket, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CredentialProviderTransportError("credential provider deadline exceeded")
        connection.settimeout(remaining)

    def _read_response(self, connection: socket.socket, deadline: float) -> bytes:
        response = bytearray()
        while True:
            self._set_remaining_timeout(connection, deadline)
            chunk = connection.recv(min(65_536, MAX_RESPONSE_BYTES + 1 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_RESPONSE_BYTES:
                raise CredentialProviderTransportError("credential provider response exceeds the byte limit")
        if not response.endswith(b"\n") or response.count(b"\n") != 1:
            raise CredentialProviderTransportError("credential provider response framing is invalid")
        return bytes(response)

    @staticmethod
    def _parse_response(response: bytes, reference: str) -> str:
        try:
            data = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CredentialProviderTransportError("credential provider response is invalid") from None
        if not isinstance(data, dict) or set(data) != {"protocol", "reference", "value"}:
            raise CredentialProviderTransportError("credential provider response fields are invalid")
        if data["protocol"] != PROTOCOL or data["reference"] != reference:
            raise CredentialProviderTransportError("credential provider response binding mismatch")
        value = data["value"]
        if not isinstance(value, str) or not value:
            raise CredentialProviderTransportError("credential provider returned no credential")
        return value
