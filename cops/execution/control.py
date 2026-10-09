"""Consume-only approval authority boundary for isolated workers.

The authority process is the only process which loads verification keys or opens
the approval database.  Workers submit an authorization identifier and the exact
plan they intend to run; they cannot submit or register an authorization.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest

from .authorization import AuthorizationTrustStore, verify_execution_authorization
from .store import ApprovalStore

REQUEST_SCHEMA = "cops.approval-control-request/v1"
RESPONSE_SCHEMA = "cops.approval-control-response/v1"
MAX_CONTROL_MESSAGE_BYTES = 1_048_576


class ApprovalControlError(RuntimeError):
    """The protected approval authority rejected or could not serve a request."""


class _DeadlineSocket:
    """Socket view that enforces one total request/response deadline.

    Recomputing the remaining timeout before every operation prevents a peer
    from extending a serial authority request by slowly dripping bytes.
    """

    def __init__(self, connection: socket.socket, deadline: float) -> None:
        self._connection = connection
        self._deadline = deadline

    def _set_remaining_timeout(self) -> None:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("approval control total connection deadline exceeded")
        self._connection.settimeout(remaining)

    def recv(self, size: int) -> bytes:
        self._set_remaining_timeout()
        return self._connection.recv(size)

    def sendall(self, data: bytes) -> None:
        self._set_remaining_timeout()
        self._connection.sendall(data)

    def getsockopt(self, *args: Any) -> Any:
        return self._connection.getsockopt(*args)


class ApprovalControl(Protocol):
    """The only approval capability exposed to an execution worker."""

    def assert_ready(self, worker_identity: str) -> None: ...

    def consume_authorization(
        self, authorization_id: str, action_plan: ActionPlan, worker_identity: str
    ) -> ApprovalConsumptionReceipt: ...

    def validate_receipt_provenance(self, receipt: ApprovalConsumptionReceipt) -> None: ...


@dataclass(frozen=True)
class ApprovalConsumptionReceipt:
    """Authority-derived proof of the exact approval consumed for execution."""

    authorization_id: str
    authorization_digest: str
    action_plan_id: str
    plan_digest: str
    engagement_id: str
    worker_identity: str
    target: str


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ApprovalControlError("Linux SO_PEERCRED support is required")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _read_json_line(connection: socket.socket) -> dict[str, Any]:
    data = bytearray()
    while True:
        chunk = connection.recv(min(65_536, MAX_CONTROL_MESSAGE_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_CONTROL_MESSAGE_BYTES:
            raise ApprovalControlError("approval control message exceeds the byte limit")
        if b"\n" in chunk:
            break
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ApprovalControlError("approval control requires one newline-delimited JSON document")
    try:
        document = json.loads(data[:-1])
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ApprovalControlError("approval control message is not valid UTF-8 JSON") from err
    if not isinstance(document, dict):
        raise ApprovalControlError("approval control message must be a JSON object")
    return document


def _write_json_line(connection: socket.socket, document: dict[str, Any]) -> None:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_CONTROL_MESSAGE_BYTES:
        raise ApprovalControlError("approval control response exceeds the byte limit")
    connection.sendall(encoded)


@dataclass(frozen=True)
class ApprovalAuthority:
    """Authority-side verifier and one-time approval consumer.

    This object intentionally has no operation that stores, creates, or signs an
    authorization from a worker request.  Operator provisioning writes approvals
    through a separate process and OS identity.
    """

    store: ApprovalStore
    trust_store: AuthorizationTrustStore
    engagement: Any
    worker_identity: str
    worker_uid: int
    worker_gid: int
    worker_pid: int
    authority_uid: int

    def assert_ready(self) -> None:
        if not sys_platform_linux():
            raise ApprovalControlError("approval authority is supported only on Linux")
        if not hasattr(os, "geteuid") or os.geteuid() != self.authority_uid:
            raise ApprovalControlError("approval authority must run as its configured OS UID")
        if self.worker_uid == self.authority_uid:
            raise ApprovalControlError("approval authority and worker require distinct OS UIDs")
        if self.worker_uid < 1 or self.worker_gid < 1 or self.worker_pid < 1:
            raise ApprovalControlError("approval authority requires a pinned non-root worker UID, GID, and PID")
        self.store.assert_protected_owner(self.authority_uid)

    def consume_document(
        self,
        document: dict[str, Any],
        *,
        peer_pid: int,
        peer_uid: int,
        peer_gid: int,
    ) -> dict[str, Any]:
        """Validate an exact plan/worker binding before atomic consumption."""
        self.assert_ready()
        expected_keys = {
            "schema_version",
            "request_id",
            "operation",
            "authorization_id",
            "worker_identity",
            "action_plan",
        }
        if set(document) != expected_keys:
            raise ApprovalControlError("approval control request has unexpected or missing fields")
        if document["schema_version"] != REQUEST_SCHEMA or document["operation"] != "consume":
            raise ApprovalControlError("unsupported approval control request")
        try:
            uuid.UUID(document["request_id"])
        except (AttributeError, TypeError, ValueError) as err:
            raise ApprovalControlError("approval control request_id must be a UUID") from err
        if peer_uid != self.worker_uid:
            raise ApprovalControlError("approval control peer UID does not match the configured worker UID")
        if peer_gid != self.worker_gid:
            raise ApprovalControlError("approval control peer GID does not match the configured worker GID")
        if peer_pid != self.worker_pid:
            raise ApprovalControlError("approval control peer PID does not match the pinned worker supervisor")
        if document["worker_identity"] != self.worker_identity:
            raise ApprovalControlError("approval control worker identity mismatch")
        if not isinstance(document["authorization_id"], str) or not document["authorization_id"]:
            raise ApprovalControlError("approval control authorization_id must be non-empty")
        try:
            plan = ActionPlan.from_dict(document["action_plan"])
        except (KeyError, TypeError, ValueError) as err:
            raise ApprovalControlError("approval control action plan is invalid") from err
        try:
            stored = self.store.get_authorization(document["authorization_id"])
            verified = verify_execution_authorization(
                stored,
                plan,
                trust_store=self.trust_store,
                engagement=self.engagement,
                worker_identity=self.worker_identity,
            )
        except Exception as err:
            raise ApprovalControlError(
                "approval authorization did not verify for the requested plan and worker"
            ) from err
        consumed = self.store.atomically_consume(
            verified.authorization_id,
            worker_identity=self.worker_identity,
            expected_authorization=verified,
        )
        self.store.assert_protected_owner(self.authority_uid)
        return {
            "schema_version": RESPONSE_SCHEMA,
            "request_id": document["request_id"],
            "ok": True,
            "authorization_id": consumed.authorization_id,
            "authorization_digest": digest(consumed.to_dict()),
            "action_plan_id": consumed.action_plan_id,
            "plan_digest": consumed.plan_digest,
            "engagement_id": consumed.engagement_id,
            "worker_identity": self.worker_identity,
            "target": plan.target,
        }

    def serve_connection(self, connection: socket.socket) -> None:
        peer_pid, peer_uid, peer_gid = _peer_credentials(connection)
        request_id: Any = None
        try:
            document = _read_json_line(connection)
            request_id = document.get("request_id")
            response = self.consume_document(
                document,
                peer_pid=peer_pid,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
            )
        except Exception:
            response = {
                "schema_version": RESPONSE_SCHEMA,
                "request_id": request_id,
                "ok": False,
                "error": "approval authority rejected the request",
            }
        _write_json_line(connection, response)


@dataclass(frozen=True)
class ApprovalAuthorityServer:
    """Protected Unix-socket server owned by the approval authority account."""

    socket_path: Path
    authority: ApprovalAuthority
    backlog: int = 16
    connection_timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        if self.connection_timeout_seconds <= 0:
            raise ValueError("approval control connection timeout must be positive")

    def _assert_socket_directory(self) -> None:
        try:
            parent_stat = os.lstat(self.socket_path.parent)
        except OSError as err:
            raise ApprovalControlError(f"approval control directory is unavailable: {err}") from err
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise ApprovalControlError("approval control parent is not a directory")
        if parent_stat.st_uid != self.authority.authority_uid:
            raise ApprovalControlError("approval control directory is not authority-owned")
        if parent_stat.st_gid != self.authority.worker_gid:
            raise ApprovalControlError("approval control directory group is not the configured worker group")
        if stat.S_IMODE(parent_stat.st_mode) != 0o2710:
            raise ApprovalControlError(
                "approval control directory must have mode 2710 (authority owner, worker group traverse)"
            )

    @contextmanager
    def listener(self) -> Iterator[socket.socket]:
        """Open a fail-closed listener without replacing an existing path."""
        self.authority.assert_ready()
        self._assert_socket_directory()
        if os.path.lexists(self.socket_path):
            raise ApprovalControlError("approval control socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.set_inheritable(False)
        try:
            previous_umask = os.umask(0o117)
            try:
                listener.bind(str(self.socket_path))
            finally:
                os.umask(previous_umask)
            os.chmod(self.socket_path, 0o660, follow_symlinks=False)
            socket_stat = os.lstat(self.socket_path)
            if not stat.S_ISSOCK(socket_stat.st_mode):
                raise ApprovalControlError("approval control path is not a Unix socket after bind")
            if socket_stat.st_uid != self.authority.authority_uid:
                raise ApprovalControlError("approval control socket is not authority-owned")
            if socket_stat.st_gid != self.authority.worker_gid:
                raise ApprovalControlError("approval control socket group is not the configured worker group")
            if stat.S_IMODE(socket_stat.st_mode) != 0o660:
                raise ApprovalControlError("approval control socket must have mode 0660")
            listener.listen(self.backlog)
            yield listener
        finally:
            listener.close()
            try:
                socket_stat = os.lstat(self.socket_path)
                if stat.S_ISSOCK(socket_stat.st_mode) and socket_stat.st_uid == self.authority.authority_uid:
                    self.socket_path.unlink()
            except FileNotFoundError:
                pass

    def serve_forever(self) -> None:
        """Serve requests serially; process supervision owns restart policy."""
        with self.listener() as listener:
            while True:
                connection, _ = listener.accept()
                try:
                    self._serve_accepted_connection(connection)
                except (ApprovalControlError, OSError):
                    # A stalled or disconnected peer must not take down the
                    # authority or prevent later workers from being served.
                    continue

    def _serve_accepted_connection(self, connection: socket.socket) -> None:
        """Bound one serial request so a peer cannot pin the authority."""
        connection.set_inheritable(False)
        with connection:
            bounded = _DeadlineSocket(
                connection,
                time.monotonic() + self.connection_timeout_seconds,
            )
            self.authority.serve_connection(bounded)  # type: ignore[arg-type]


@dataclass(frozen=True)
class ApprovalControlClient:
    """Worker-side consume-only client for a separately owned Unix socket."""

    socket_path: Path
    expected_authority_uid: int
    worker_uid: int | None = None
    worker_gid: int | None = None
    timeout_seconds: float = 5.0
    _issued_receipts: dict[int, ApprovalConsumptionReceipt] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def validate_receipt_provenance(self, receipt: ApprovalConsumptionReceipt) -> None:
        if self._issued_receipts.pop(id(receipt), None) is not receipt:
            raise ApprovalControlError("approval receipt was not issued by this control client")

    def assert_ready(self, worker_identity: str) -> None:
        del worker_identity
        if not sys_platform_linux():
            raise ApprovalControlError("production approval control is supported only on Linux")
        actual_uid = os.geteuid()
        actual_gid = os.getegid()
        current_uid = actual_uid if self.worker_uid is None else self.worker_uid
        current_gid = actual_gid if self.worker_gid is None else self.worker_gid
        if current_uid != actual_uid or current_gid != actual_gid:
            raise ApprovalControlError("configured worker UID/GID do not match the running process")
        if current_uid == 0:
            raise ApprovalControlError("approval worker must not run as root")
        if current_uid == self.expected_authority_uid:
            raise ApprovalControlError("approval authority and worker require distinct OS UIDs")
        try:
            socket_stat = os.lstat(self.socket_path)
            parent_stat = os.lstat(self.socket_path.parent)
        except OSError as err:
            raise ApprovalControlError(f"approval authority socket is unavailable: {err}") from err
        if not stat.S_ISSOCK(socket_stat.st_mode):
            raise ApprovalControlError("approval authority path is not a Unix socket")
        if socket_stat.st_uid != self.expected_authority_uid:
            raise ApprovalControlError("approval authority socket owner does not match configured UID")
        if socket_stat.st_gid != current_gid:
            raise ApprovalControlError("approval authority socket group does not match the worker GID")
        if stat.S_IMODE(socket_stat.st_mode) != 0o660:
            raise ApprovalControlError("approval authority socket must have mode 0660")
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != self.expected_authority_uid:
            raise ApprovalControlError("approval authority socket directory is not authority-owned")
        if parent_stat.st_gid != current_gid:
            raise ApprovalControlError("approval authority socket directory group does not match the worker GID")
        if stat.S_IMODE(parent_stat.st_mode) != 0o2710:
            raise ApprovalControlError("approval authority socket directory must have mode 2710")

    def consume_authorization(
        self, authorization_id: str, action_plan: ActionPlan, worker_identity: str
    ) -> ApprovalConsumptionReceipt:
        self.assert_ready(worker_identity)
        request_id = str(uuid.uuid4())
        request = {
            "schema_version": REQUEST_SCHEMA,
            "request_id": request_id,
            "operation": "consume",
            "authorization_id": authorization_id,
            "worker_identity": worker_identity,
            "action_plan": action_plan.to_dict(),
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.set_inheritable(False)
            connection.settimeout(self.timeout_seconds)
            connection.connect(str(self.socket_path))
            _, peer_uid, _ = _peer_credentials(connection)
            if peer_uid != self.expected_authority_uid:
                raise ApprovalControlError("connected approval authority UID does not match configured UID")
            _write_json_line(connection, request)
            response = _read_json_line(connection)
        if response.get("schema_version") != RESPONSE_SCHEMA or response.get("request_id") != request_id:
            raise ApprovalControlError("approval authority response identity mismatch")
        if response.get("ok") is not True:
            raise ApprovalControlError(str(response.get("error", "approval authority rejected the request")))
        if set(response) != {
            "schema_version",
            "request_id",
            "ok",
            "authorization_id",
            "authorization_digest",
            "action_plan_id",
            "plan_digest",
            "engagement_id",
            "worker_identity",
            "target",
        }:
            raise ApprovalControlError("approval authority response has unexpected or missing fields")
        if response["authorization_id"] != authorization_id:
            raise ApprovalControlError("approval authority returned a different authorization")
        authorization_digest = response["authorization_digest"]
        if not isinstance(authorization_digest, str) or len(authorization_digest) != 64:
            raise ApprovalControlError("approval authority returned an invalid authorization digest")
        exact_bindings = {
            "action_plan_id": action_plan.plan_id,
            "plan_digest": action_plan.plan_digest,
            "engagement_id": action_plan.engagement_id,
            "worker_identity": worker_identity,
            "target": action_plan.target,
        }
        for binding_name, expected in exact_bindings.items():
            value = response[binding_name]
            if not isinstance(value, str) or not value:
                raise ApprovalControlError(f"approval authority returned an invalid {binding_name} binding")
            if value != expected:
                raise ApprovalControlError(f"approval authority returned a mismatched {binding_name} binding")
        receipt = ApprovalConsumptionReceipt(
            authorization_id=authorization_id,
            authorization_digest=authorization_digest,
            action_plan_id=response["action_plan_id"],
            plan_digest=response["plan_digest"],
            engagement_id=response["engagement_id"],
            worker_identity=response["worker_identity"],
            target=response["target"],
        )
        self._issued_receipts[id(receipt)] = receipt
        return receipt


def sys_platform_linux() -> bool:
    return os.name == "posix" and __import__("sys").platform.startswith("linux")
