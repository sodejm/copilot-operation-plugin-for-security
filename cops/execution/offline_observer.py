"""Offline-only verification of a local observer's signed attestation.

This module deliberately has no execution capability.  It accepts only a
bounded, one-shot UNIX-domain response and verifies that a host observer
bound it to the current worker and the requested gate metadata.
"""

from __future__ import annotations

import os
import socket
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cops.evidence.canonical import EvidenceError, canonical, decode_json

REQUEST_SCHEMA = "cops.offline-observer-request/v1"
ATTESTATION_SCHEMA = "cops.offline-observer-attestation/v1"
MAX_OBSERVER_MESSAGE_BYTES = 65_536
ATTESTATION_TTL_NS = 2_000_000_000
_PHASES = frozenset({"approval", "release"})
_GATE_KEYS = frozenset({"child_pid", "gate_fd", "gate_device", "gate_inode"})
_BODY_KEYS = frozenset(
    {
        "schema_version",
        "phase",
        "authorization_id",
        "plan_digest",
        "worker_identity",
        "worker_pid",
        "isolation_digest",
        "gate",
        "nonce",
        "observed_monotonic_ns",
    }
)
_DOCUMENT_KEYS = _BODY_KEYS | {"signature"}
_REQUEST_KEYS = _BODY_KEYS - {"observed_monotonic_ns"}
_HEX = frozenset("0123456789abcdef")


def _fail(code: str) -> None:
    raise ValueError(code)


def _string(value: object, code: str) -> str:
    if type(value) is not str or not value:
        _fail(code)
    return value


def _digest(value: object, code: str) -> str:
    value = _string(value, code)
    if len(value) != 64 or any(char not in _HEX for char in value):
        _fail(code)
    return value


def _positive_int(value: object, code: str) -> int:
    if type(value) is not int or value <= 0:
        _fail(code)
    return value


def _phase(value: object) -> str:
    value = _string(value, "invalid_phase")
    if value not in _PHASES:
        _fail("invalid_phase")
    return value


def _nonce(value: object) -> str:
    value = _string(value, "invalid_nonce")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        _fail("invalid_nonce")
    if parsed.version != 4 or str(parsed) != value:
        _fail("invalid_nonce")
    return value


def _gate(value: object) -> dict[str, int] | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != _GATE_KEYS:
        _fail("invalid_gate")
    gate = {key: _positive_int(value[key], "invalid_gate") for key in _GATE_KEYS - {"gate_fd"}}
    if type(value["gate_fd"]) is not int or value["gate_fd"] < 0:
        _fail("invalid_gate")
    gate["gate_fd"] = value["gate_fd"]
    return gate


def _attestation_body(document: dict[str, Any]) -> dict[str, Any]:
    if type(document) is not dict or set(document) != _DOCUMENT_KEYS:
        _fail("invalid_attestation")
    body = {key: document[key] for key in _BODY_KEYS}
    if body["schema_version"] != ATTESTATION_SCHEMA:
        _fail("invalid_schema")
    _phase(body["phase"])
    _string(body["authorization_id"], "invalid_authorization_id")
    _digest(body["plan_digest"], "invalid_plan_digest")
    _string(body["worker_identity"], "invalid_worker_identity")
    _positive_int(body["worker_pid"], "invalid_worker_pid")
    _digest(body["isolation_digest"], "invalid_isolation_digest")
    if _gate(body["gate"]) is None:
        _fail("invalid_gate")
    _nonce(body["nonce"])
    _positive_int(body["observed_monotonic_ns"], "invalid_observed_time")
    return body


def parse_observer_request(raw: bytes) -> dict[str, Any]:
    """Parse one canonical observer request frame for the local broker.

    The caller supplies the complete frame, including its required trailing
    newline.  This deliberately has no socket or process-control side effects.
    """

    if type(raw) is not bytes or len(raw) > MAX_OBSERVER_MESSAGE_BYTES:
        _fail("invalid_observer_request")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        _fail("invalid_observer_request")
    try:
        request = decode_json(raw[:-1], max_bytes=MAX_OBSERVER_MESSAGE_BYTES)
        if type(request) is not dict or set(request) != _REQUEST_KEYS:
            _fail("invalid_observer_request")
        if raw[:-1] != canonical(request, max_bytes=MAX_OBSERVER_MESSAGE_BYTES):
            _fail("noncanonical_observer_request")
    except EvidenceError:
        _fail("invalid_observer_request")
    if request["schema_version"] != REQUEST_SCHEMA:
        _fail("invalid_schema")
    _phase(request["phase"])
    _string(request["authorization_id"], "invalid_authorization_id")
    _digest(request["plan_digest"], "invalid_plan_digest")
    _string(request["worker_identity"], "invalid_worker_identity")
    _positive_int(request["worker_pid"], "invalid_worker_pid")
    _digest(request["isolation_digest"], "invalid_isolation_digest")
    if _gate(request["gate"]) is None:
        _fail("invalid_gate")
    _nonce(request["nonce"])
    return request


@dataclass(frozen=True)
class ObserverVerifier:
    """Verifies a bounded, detached Ed25519 observer attestation."""

    public_key: bytes

    def __post_init__(self) -> None:
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            _fail("invalid_observer_public_key")
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key)
        except ValueError:
            _fail("invalid_observer_public_key")

    def verify(
        self,
        document: dict[str, Any],
        *,
        phase: str,
        authorization_id: str,
        plan_digest: str,
        worker_identity: str,
        worker_pid: int,
        isolation_digest: str | None = None,
        gate: dict[str, int] | None = None,
        nonce: str | None = None,
    ) -> None:
        """Raise ``ValueError`` unless the attestation is current and bound exactly."""

        expected_phase = _phase(phase)
        expected_authorization_id = _string(authorization_id, "invalid_authorization_id")
        expected_plan_digest = _digest(plan_digest, "invalid_plan_digest")
        expected_worker_identity = _string(worker_identity, "invalid_worker_identity")
        expected_worker_pid = _positive_int(worker_pid, "invalid_worker_pid")
        expected_isolation_digest = (
            None if isolation_digest is None else _digest(isolation_digest, "invalid_isolation_digest")
        )
        expected_gate = _gate(gate)
        expected_nonce = None if nonce is None else _nonce(nonce)

        body = _attestation_body(document)
        signature = document["signature"]
        if type(signature) is not str or len(signature) != 128 or any(char not in _HEX for char in signature):
            _fail("invalid_signature")
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                bytes.fromhex(signature), canonical(body, max_bytes=MAX_OBSERVER_MESSAGE_BYTES)
            )
        except (InvalidSignature, ValueError, EvidenceError):
            _fail("invalid_signature")

        if (
            body["phase"] != expected_phase
            or body["authorization_id"] != expected_authorization_id
            or body["plan_digest"] != expected_plan_digest
            or body["worker_identity"] != expected_worker_identity
            or body["worker_pid"] != expected_worker_pid
            or (expected_isolation_digest is not None and body["isolation_digest"] != expected_isolation_digest)
            or (expected_gate is not None and body["gate"] != expected_gate)
            or (expected_nonce is not None and body["nonce"] != expected_nonce)
        ):
            _fail("attestation_binding_mismatch")

        now = time.monotonic_ns()
        observed = body["observed_monotonic_ns"]
        if observed > now or now - observed > ATTESTATION_TTL_NS:
            _fail("stale_attestation")


def _peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        _fail("peer_credentials_unavailable")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
    except (OSError, struct.error):
        _fail("peer_credentials_unavailable")
    if pid <= 0:
        _fail("invalid_peer_credentials")
    return uid


def _read_response(connection: socket.socket, deadline: float) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("observer_timeout")
        try:
            connection.settimeout(remaining)
            chunk = connection.recv(min(4096, MAX_OBSERVER_MESSAGE_BYTES + 1 - size))
        except (OSError, TimeoutError):
            _fail("observer_response_unavailable")
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_OBSERVER_MESSAGE_BYTES:
            _fail("observer_response_limit")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        _fail("invalid_observer_response")
    return raw[:-1]


@dataclass(frozen=True)
class ObserverClient:
    """Offline local UNIX client for a pinned host observer."""

    socket_path: Path
    expected_observer_uid: int
    verifier: ObserverVerifier

    def __post_init__(self) -> None:
        if not isinstance(self.socket_path, Path) or not self.socket_path.is_absolute():
            _fail("invalid_observer_socket_path")
        if type(self.expected_observer_uid) is not int or self.expected_observer_uid < 0:
            _fail("invalid_observer_uid")
        if not isinstance(self.verifier, ObserverVerifier):
            _fail("invalid_observer_verifier")

    def attest(
        self,
        *,
        phase: str,
        authorization_id: str,
        plan_digest: str,
        worker_identity: str,
        isolation_digest: str,
        gate: dict[str, int],
    ) -> dict[str, Any]:
        """Request and strictly validate one fresh, local observer attestation."""

        phase = _phase(phase)
        authorization_id = _string(authorization_id, "invalid_authorization_id")
        plan_digest = _digest(plan_digest, "invalid_plan_digest")
        worker_identity = _string(worker_identity, "invalid_worker_identity")
        isolation_digest = _digest(isolation_digest, "invalid_isolation_digest")
        gate = _gate(gate)
        assert gate is not None  # The public client contract requires a gate.
        worker_pid = os.getpid()
        nonce = str(uuid.uuid4())
        request = {
            "schema_version": REQUEST_SCHEMA,
            "phase": phase,
            "authorization_id": authorization_id,
            "plan_digest": plan_digest,
            "worker_identity": worker_identity,
            "worker_pid": worker_pid,
            "isolation_digest": isolation_digest,
            "gate": gate,
            "nonce": nonce,
        }
        try:
            frame = canonical(request, max_bytes=MAX_OBSERVER_MESSAGE_BYTES) + b"\n"
        except EvidenceError:
            _fail("invalid_observer_request")

        deadline = time.monotonic() + (ATTESTATION_TTL_NS / 1_000_000_000)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                connection.connect(os.fspath(self.socket_path))
                if _peer_uid(connection) != self.expected_observer_uid:
                    _fail("observer_uid_mismatch")
                connection.sendall(frame)
                connection.shutdown(socket.SHUT_WR)
                raw = _read_response(connection, deadline)
        except ValueError:
            raise
        except (OSError, TimeoutError):
            _fail("observer_connection_unavailable")

        try:
            document = decode_json(raw, max_bytes=MAX_OBSERVER_MESSAGE_BYTES)
        except EvidenceError:
            _fail("invalid_observer_response")
        if type(document) is not dict:
            _fail("invalid_observer_response")
        try:
            if raw != canonical(document, max_bytes=MAX_OBSERVER_MESSAGE_BYTES):
                _fail("noncanonical_observer_response")
        except EvidenceError:
            _fail("invalid_observer_response")
        self.verifier.verify(
            document,
            phase=phase,
            authorization_id=authorization_id,
            plan_digest=plan_digest,
            worker_identity=worker_identity,
            worker_pid=worker_pid,
            isolation_digest=isolation_digest,
            gate=gate,
            nonce=nonce,
        )
        return document
