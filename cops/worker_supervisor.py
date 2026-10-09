"""Persistent, unprivileged worker behind the pinned SSH relay.

The SSH login account can only send a framed request over the supervisor socket.
Approval creation, verifier keys, and the approval database stay in a separate
authority process reached through the consume-only control client.
"""

from __future__ import annotations

import io
import json
import math
import os
import re
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any

from cops.adapters import ToolAdapterRegistry
from cops.contracts.models import Engagement
from cops.execution.control import ApprovalControlClient
from cops.execution.credential_provider import UnixSocketCredentialProvider
from cops.execution.credentials import CredentialGrant, ScopedCredentialResolver
from cops.execution.egress import CertificateURIIdentityVerifier
from cops.execution.filesystem import open_directory_no_symlinks
from cops.execution.sandbox import LinuxBubblewrapSandbox
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.execution.supervisor_attestation import (
    SupervisorAttestationError,
    SupervisorResponseAttestor,
    validate_attestation_key_id,
)
from cops.execution.worker import IsolatedWorker, WorkerCapabilityInventory
from cops.remote_worker import SSHRemoteExecutionReceiver

CONFIG_SCHEMA = "cops.worker-supervisor-config/v1"
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
CREDENTIAL_MANIFEST_SCHEMA = "cops.worker-credential-manifest/v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ENVIRONMENT_VARIABLE_RE = re.compile(r"COPS_CREDENTIAL_[A-Z0-9_]+")


class WorkerSupervisorError(RuntimeError):
    """The supervisor could not establish or preserve its trust boundary."""


def _owner_only_json(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise WorkerSupervisorError("supervisor input path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent = open_directory_no_symlinks(path.parent)
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent)
        finally:
            os.close(parent)
    except OSError as err:
        raise WorkerSupervisorError("supervisor input is unavailable") from err
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise WorkerSupervisorError("supervisor input must be an account-owned regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkerSupervisorError("supervisor input must be owner-only")
        with os.fdopen(descriptor, encoding="utf-8") as source:
            descriptor = -1
            data = json.load(source)
    except (OSError, ValueError) as err:
        raise WorkerSupervisorError("supervisor input is invalid JSON") from err
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(data, dict):
        raise WorkerSupervisorError("supervisor input must be a JSON object")
    return data


@dataclass(frozen=True)
class WorkerSupervisorConfig:
    expected_host: str
    worker_identity: str
    socket_path: Path
    relay_uid: int
    relay_gid: int
    supervisor_uid: int
    supervisor_gid: int
    authority_uid: int
    approval_socket_path: Path
    inventory_path: Path
    engagement_path: Path
    attestation_key_id: str
    attestation_key_path: Path
    executable_sha256_pins: dict[str, str]
    egress_trust_domain: str | None = None
    credential_manifest_path: Path | None = None

    @classmethod
    def from_file(cls, path: Path | str) -> WorkerSupervisorConfig:
        data = _owner_only_json(Path(path))
        required = {
            "schema_version",
            "expected_host",
            "worker_identity",
            "socket_path",
            "relay_uid",
            "relay_gid",
            "supervisor_uid",
            "supervisor_gid",
            "authority_uid",
            "approval_socket_path",
            "inventory_path",
            "engagement_path",
            "attestation_key_id",
            "attestation_key_path",
            "executable_sha256_pins",
        }
        optional = {"egress_trust_domain", "credential_manifest_path"}
        fields = set(data)
        if not required <= fields or fields - required - optional:
            raise WorkerSupervisorError("supervisor configuration fields or schema are invalid")
        if data["schema_version"] != CONFIG_SCHEMA:
            raise WorkerSupervisorError("supervisor configuration fields or schema are invalid")
        for key in ("expected_host", "worker_identity"):
            if not isinstance(data[key], str) or not data[key].strip():
                raise WorkerSupervisorError(f"supervisor {key} must be non-empty")
        try:
            validate_attestation_key_id(data["attestation_key_id"])
        except SupervisorAttestationError as err:
            raise WorkerSupervisorError("supervisor attestation key ID is invalid") from err
        for key in ("relay_uid", "relay_gid", "supervisor_uid", "supervisor_gid", "authority_uid"):
            if type(data[key]) is not int or data[key] < 1:
                raise WorkerSupervisorError(f"supervisor {key} must be a non-root integer")
        if data["relay_uid"] in (data["supervisor_uid"], data["authority_uid"]):
            raise WorkerSupervisorError("relay, supervisor, and authority require separate UIDs")
        if data["supervisor_uid"] == data["authority_uid"]:
            raise WorkerSupervisorError("supervisor and authority require separate UIDs")
        if (os.geteuid(), os.getegid()) != (data["supervisor_uid"], data["supervisor_gid"]):
            raise WorkerSupervisorError("supervisor account does not match the configured UID/GID")
        for key in (
            "socket_path",
            "approval_socket_path",
            "inventory_path",
            "engagement_path",
            "attestation_key_path",
        ):
            if not isinstance(data[key], str) or not Path(data[key]).is_absolute():
                raise WorkerSupervisorError(f"supervisor {key} must be an absolute path")
        pins = data["executable_sha256_pins"]
        if not isinstance(pins, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in pins.items()):
            raise WorkerSupervisorError("supervisor executable pins must be a string mapping")
        egress_trust_domain = data.get("egress_trust_domain")
        if egress_trust_domain is not None:
            if not isinstance(egress_trust_domain, str):
                raise WorkerSupervisorError("supervisor egress trust domain is invalid")
            try:
                CertificateURIIdentityVerifier(trust_domain=egress_trust_domain)
            except ValueError as err:
                raise WorkerSupervisorError("supervisor egress trust domain is invalid") from err
        credential_manifest_path = data.get("credential_manifest_path")
        if credential_manifest_path is not None:
            if not isinstance(credential_manifest_path, str) or not Path(credential_manifest_path).is_absolute():
                raise WorkerSupervisorError("supervisor credential manifest path must be absolute")
        return cls(
            expected_host=data["expected_host"],
            worker_identity=data["worker_identity"],
            socket_path=Path(data["socket_path"]),
            relay_uid=data["relay_uid"],
            relay_gid=data["relay_gid"],
            supervisor_uid=data["supervisor_uid"],
            supervisor_gid=data["supervisor_gid"],
            authority_uid=data["authority_uid"],
            approval_socket_path=Path(data["approval_socket_path"]),
            inventory_path=Path(data["inventory_path"]),
            engagement_path=Path(data["engagement_path"]),
            attestation_key_id=data["attestation_key_id"],
            attestation_key_path=Path(data["attestation_key_path"]),
            executable_sha256_pins=pins,
            egress_trust_domain=egress_trust_domain,
            credential_manifest_path=(Path(credential_manifest_path) if credential_manifest_path is not None else None),
        )


def _credential_resolver(
    config: WorkerSupervisorConfig,
    *,
    engagement_id: str,
    approval_control: ApprovalControlClient,
) -> ScopedCredentialResolver | None:
    if config.credential_manifest_path is None:
        return None
    data = _owner_only_json(config.credential_manifest_path)
    required = {
        "schema_version",
        "provider_socket_path",
        "provider_uid",
        "provider_gid",
        "provider_timeout_seconds",
        "grants",
    }
    if set(data) != required or data["schema_version"] != CREDENTIAL_MANIFEST_SCHEMA:
        raise WorkerSupervisorError("credential manifest fields or schema are invalid")
    provider_path = data["provider_socket_path"]
    if not isinstance(provider_path, str) or not Path(provider_path).is_absolute():
        raise WorkerSupervisorError("credential provider socket path must be absolute")
    for key in ("provider_uid", "provider_gid"):
        if type(data[key]) is not int or data[key] < 1:
            raise WorkerSupervisorError(f"credential {key} must be a non-root integer")
    if data["provider_uid"] in (config.relay_uid, config.supervisor_uid, config.authority_uid):
        raise WorkerSupervisorError("credential provider requires a separate UID")
    provider_timeout = data["provider_timeout_seconds"]
    if (
        not isinstance(provider_timeout, (int, float))
        or isinstance(provider_timeout, bool)
        or not math.isfinite(provider_timeout)
        or provider_timeout <= 0
        or provider_timeout > 30
    ):
        raise WorkerSupervisorError("credential provider timeout must be between 0 and 30 seconds")
    raw_grants = data["grants"]
    if not isinstance(raw_grants, list):
        raise WorkerSupervisorError("credential grants must be a list")

    manifest_grant_fields = {
        "reference",
        "environment_variable",
        "plan_id",
        "plan_digest",
        "engagement_id",
        "worker_identity",
        "target",
        "operation_index",
        "operation_digest",
        "step_id",
        "tool",
        "tool_version",
        "action",
    }
    model_grant_fields = {field.name for field in dataclass_fields(CredentialGrant)}
    if model_grant_fields != manifest_grant_fields:
        raise WorkerSupervisorError("credential grant model does not support exact operation binding")
    grants: list[CredentialGrant] = []
    seen: set[tuple[str, int, str, str]] = set()
    for raw_grant in raw_grants:
        if not isinstance(raw_grant, dict) or set(raw_grant) != manifest_grant_fields:
            raise WorkerSupervisorError("credential grant fields are invalid")
        string_fields = manifest_grant_fields - {"operation_index"}
        if any(not isinstance(raw_grant[key], str) or not raw_grant[key] for key in string_fields):
            raise WorkerSupervisorError("credential grant string fields must be non-empty")
        if type(raw_grant["operation_index"]) is not int or raw_grant["operation_index"] < 0:
            raise WorkerSupervisorError("credential operation index must be a non-negative integer")
        if not _ENVIRONMENT_VARIABLE_RE.fullmatch(raw_grant["environment_variable"]):
            raise WorkerSupervisorError("credential environment variable is invalid")
        if not _SHA256_RE.fullmatch(raw_grant["plan_digest"]) or not _SHA256_RE.fullmatch(
            raw_grant["operation_digest"]
        ):
            raise WorkerSupervisorError("credential grant digest is invalid")
        if raw_grant["engagement_id"] != engagement_id:
            raise WorkerSupervisorError("credential grant engagement does not match the supervisor")
        if raw_grant["worker_identity"] != config.worker_identity:
            raise WorkerSupervisorError("credential grant worker does not match the supervisor")
        identity = (
            raw_grant["plan_id"],
            raw_grant["operation_index"],
            raw_grant["reference"],
            raw_grant["environment_variable"],
        )
        if identity in seen:
            raise WorkerSupervisorError("credential manifest contains a duplicate grant")
        seen.add(identity)
        grants.append(CredentialGrant(**raw_grant))

    provider = UnixSocketCredentialProvider(
        provider_path,
        expected_provider_uid=data["provider_uid"],
        expected_provider_gid=data["provider_gid"],
        default_timeout_seconds=float(provider_timeout),
    )
    return ScopedCredentialResolver(provider, grants, approval_control=approval_control)


def build_receiver(config: WorkerSupervisorConfig) -> SSHRemoteExecutionReceiver:
    """Build the production worker using only provisioned local inputs."""
    inventory = WorkerCapabilityInventory.from_file(
        config.inventory_path, expected_worker_identity=config.worker_identity
    )
    engagement = Engagement.from_dict(_owner_only_json(config.engagement_path))
    control = ApprovalControlClient(
        socket_path=config.approval_socket_path,
        expected_authority_uid=config.authority_uid,
        worker_uid=config.supervisor_uid,
        worker_gid=config.supervisor_gid,
    )
    credential_resolver = _credential_resolver(
        config,
        engagement_id=engagement.engagement_id,
        approval_control=control,
    )
    sandbox = LinuxBubblewrapSandbox(worker_uid=config.supervisor_uid, worker_gid=config.supervisor_gid)
    worker = IsolatedWorker(
        inventory,
        control,
        sandbox,
        scope_guard=ScopeGuard(
            ScopeDefinition.from_engagement_scope(
                engagement.scope,
                egress_allowed=config.egress_trust_domain is not None,
            )
        ),
        adapter_registry=ToolAdapterRegistry(executable_sha256_pins=config.executable_sha256_pins),
        expected_engagement_id=engagement.engagement_id,
        egress_trust_domain=config.egress_trust_domain,
        credential_resolver=credential_resolver,
    )
    return SSHRemoteExecutionReceiver(
        expected_host=config.expected_host,
        expected_worker_identity=config.worker_identity,
        worker=worker,
    )


def _read_complete_request(connection: socket.socket, deadline: float) -> bytes:
    """Wait for write shutdown before execution, rejecting trailing or partial bytes."""
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WorkerSupervisorError("relay request deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(min(65_536, MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_REQUEST_BYTES:
            raise WorkerSupervisorError("relay request exceeds the byte limit")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise WorkerSupervisorError("relay requires one complete newline-delimited request")
    return bytes(data)


def serve_connection(
    connection: socket.socket,
    config: WorkerSupervisorConfig,
    receiver: SSHRemoteExecutionReceiver,
    attestor: SupervisorResponseAttestor,
    *,
    timeout_seconds: float = 30.0,
) -> None:
    """Handle exactly one authenticated relay connection."""
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise WorkerSupervisorError("Linux peer credentials are required")
    raw_credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, peer_uid, peer_gid = struct.unpack("3i", raw_credentials)
    if (peer_uid, peer_gid) != (config.relay_uid, config.relay_gid):
        raise WorkerSupervisorError("relay peer identity mismatch")
    request_deadline = time.monotonic() + timeout_seconds
    request = _read_complete_request(connection, request_deadline)
    output = io.BytesIO()
    receiver.serve_one(io.BytesIO(request), output)
    response = attestor.attest(request, output.getvalue())
    if len(response) > MAX_RESPONSE_BYTES or not response.endswith(b"\n") or response.count(b"\n") != 1:
        raise WorkerSupervisorError("worker response framing or byte limit is invalid")
    # The worker enforces the approved execution timeout. This deadline only
    # bounds response delivery after execution has completed.
    response_deadline = time.monotonic() + timeout_seconds
    remaining = response_deadline - time.monotonic()
    if remaining <= 0:
        raise WorkerSupervisorError("relay response deadline exceeded")
    connection.settimeout(remaining)
    connection.sendall(response)


def serve_forever(config: WorkerSupervisorConfig, receiver: SSHRemoteExecutionReceiver) -> None:
    """Bind a pre-provisioned directory and serve a single request per connection."""
    if sys.platform != "linux":
        raise WorkerSupervisorError("production supervisor requires Linux")
    attestor = SupervisorResponseAttestor.from_file(
        config.attestation_key_id,
        config.attestation_key_path,
    )
    try:
        parent_descriptor = open_directory_no_symlinks(config.socket_path.parent)
        try:
            parent = os.fstat(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as err:
        raise WorkerSupervisorError("supervisor socket directory is unavailable") from err
    if (
        not stat.S_ISDIR(parent.st_mode)
        or (parent.st_uid, parent.st_gid) != (config.supervisor_uid, config.supervisor_gid)
        or stat.S_IMODE(parent.st_mode) != 0o2710
    ):
        raise WorkerSupervisorError("supervisor socket directory ownership or mode is unsafe")
    if config.socket_path.exists() or config.socket_path.is_symlink():
        raise WorkerSupervisorError("supervisor socket path already exists")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        old_umask = os.umask(0o117)
        try:
            listener.bind(str(config.socket_path))
        finally:
            os.umask(old_umask)
        os.chmod(config.socket_path, 0o660)
        bound = os.lstat(config.socket_path)
        if not stat.S_ISSOCK(bound.st_mode) or (bound.st_uid, bound.st_gid) != (
            config.supervisor_uid,
            config.supervisor_gid,
        ):
            raise WorkerSupervisorError("bound supervisor socket identity is unsafe")
        listener.listen(8)
        try:
            while True:
                connection, _ = listener.accept()
                with connection:
                    try:
                        serve_connection(connection, config, receiver, attestor)
                    except (OSError, ValueError, RuntimeError):
                        # The relay receives EOF; errors must not expose local paths or secrets.
                        continue
        finally:
            config.socket_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "--config":
        print("usage: python3 -m cops.worker_supervisor --config ABSOLUTE_PATH", file=sys.stderr)
        return 2
    try:
        config = WorkerSupervisorConfig.from_file(args[1])
        receiver = build_receiver(config)
        serve_forever(config, receiver)
    except (OSError, ValueError, RuntimeError):
        print("worker supervisor readiness or service failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
