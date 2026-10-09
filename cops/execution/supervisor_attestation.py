"""Authenticate remote worker responses at the protected supervisor boundary."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cops.evidence.canonical import canonical, decode_json, digest

from .filesystem import SecureDirectoryError, open_directory_no_symlinks

ATTESTED_AUTHORIZED_RUN_SCHEMA = "cops.attested-remote-authorized-run/v1"
SUPERVISOR_ATTESTATION_SCHEMA = "cops.supervisor-response-attestation/v1"
SSH_PROTOCOL = "cops.remote-worker/v1"
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{43}")
_HEX_KEY = re.compile(rb"[0-9a-f]{64}")
_MAC = re.compile(r"[0-9a-f]{64}")


class SupervisorAttestationError(RuntimeError):
    """A supervisor response could not be authenticated."""


def validate_exchange_nonce(value: object) -> str:
    if not isinstance(value, str) or _NONCE.fullmatch(value) is None:
        raise SupervisorAttestationError("remote exchange nonce is invalid")
    return value


def validate_attestation_key_id(value: object) -> str:
    if not isinstance(value, str) or _IDENTITY.fullmatch(value) is None:
        raise SupervisorAttestationError("supervisor attestation key ID is invalid")
    return value


def load_attestation_key(path: Path | str) -> bytes:
    """Load an owner-only 256-bit HMAC key without following links."""
    source = Path(path)
    if not source.is_absolute() or source.name in ("", ".", ".."):
        raise SupervisorAttestationError("supervisor attestation key path is invalid")
    _validate_ancestor_directories(source.parent)
    parent_fd = descriptor = -1
    try:
        parent_fd = open_directory_no_symlinks(source.parent)
        descriptor = os.open(
            source.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise SupervisorAttestationError("supervisor attestation key file is not protected")
        raw = os.read(descriptor, 66)
    except SupervisorAttestationError:
        raise
    except (OSError, SecureDirectoryError) as err:
        raise SupervisorAttestationError("supervisor attestation key is unavailable") from err
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)
    if _HEX_KEY.fullmatch(raw) is None:
        raise SupervisorAttestationError("supervisor attestation key encoding is invalid")
    return bytes.fromhex(raw.decode("ascii"))


def _validate_ancestor_directories(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except OSError as err:
            raise SupervisorAttestationError("supervisor attestation key ancestry is unavailable") from err
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SupervisorAttestationError("supervisor attestation key ancestry is unsafe")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
            raise SupervisorAttestationError("supervisor attestation key ancestry is writable")


class SupervisorResponseAttestor:
    """Sign the exact supervisor request and authorized-run response."""

    def __init__(self, key_id: str, key: bytes) -> None:
        self._key_id = validate_attestation_key_id(key_id)
        if not isinstance(key, bytes) or len(key) != 32:
            raise SupervisorAttestationError("supervisor attestation key must contain 32 bytes")
        self._key = key

    @classmethod
    def from_file(cls, key_id: str, key_path: Path | str) -> SupervisorResponseAttestor:
        return cls(key_id, load_attestation_key(key_path))

    def attest(self, request: bytes, response: bytes) -> bytes:
        request_document = _decode_line(request, "request")
        response_document = _decode_line(response, "response")
        claims, authorized_run = _claims_from_documents(request_document, response_document)
        unsigned = {
            "schema_version": SUPERVISOR_ATTESTATION_SCHEMA,
            "key_id": self._key_id,
            "claims": claims,
        }
        wrapper = {
            "schema_version": ATTESTED_AUTHORIZED_RUN_SCHEMA,
            "authorized_run": authorized_run,
            "attestation": {**unsigned, "mac": _mac(self._key, unsigned)},
        }
        signed_response = dict(response_document)
        signed_response["payload"] = wrapper
        return canonical(signed_response) + b"\n"


def verify_attested_authorized_run(
    payload: Mapping[str, object],
    *,
    attestation_key_id: str,
    attestation_key: bytes,
    request_id: str,
    exchange_nonce: str,
    host: str,
    worker_identity: str,
    authorization_id: str,
    action_plan_document: Mapping[str, object],
    timeout_seconds: float,
    max_output_bytes: int,
) -> Mapping[str, object]:
    """Verify an attested payload before its result is reconstructed or accepted."""
    validate_attestation_key_id(attestation_key_id)
    validate_exchange_nonce(exchange_nonce)
    if not isinstance(attestation_key, bytes) or len(attestation_key) != 32:
        raise SupervisorAttestationError("supervisor attestation key must contain 32 bytes")
    if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "authorized_run", "attestation"}:
        raise SupervisorAttestationError("remote attested response fields are invalid")
    if payload["schema_version"] != ATTESTED_AUTHORIZED_RUN_SCHEMA:
        raise SupervisorAttestationError("remote attested response schema is unsupported")
    run = payload["authorized_run"]
    attestation = payload["attestation"]
    if not isinstance(run, Mapping) or not isinstance(attestation, Mapping):
        raise SupervisorAttestationError("remote attested response payload is invalid")
    if set(attestation) != {"schema_version", "key_id", "claims", "mac"}:
        raise SupervisorAttestationError("remote response attestation fields are invalid")
    if attestation["schema_version"] != SUPERVISOR_ATTESTATION_SCHEMA:
        raise SupervisorAttestationError("remote response attestation schema is unsupported")
    if attestation["key_id"] != attestation_key_id:
        raise SupervisorAttestationError("remote response attestation key ID mismatch")
    mac = attestation["mac"]
    if not isinstance(mac, str) or _MAC.fullmatch(mac) is None:
        raise SupervisorAttestationError("remote response attestation MAC is invalid")
    expected_claims = _build_claims(
        request_id=request_id,
        exchange_nonce=exchange_nonce,
        host=host,
        worker_identity=worker_identity,
        authorization_id=authorization_id,
        action_plan=action_plan_document,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        authorized_run=run,
    )
    if attestation["claims"] != expected_claims:
        raise SupervisorAttestationError("remote response attestation binding mismatch")
    unsigned = {
        "schema_version": SUPERVISOR_ATTESTATION_SCHEMA,
        "key_id": attestation_key_id,
        "claims": expected_claims,
    }
    if not hmac.compare_digest(mac, _mac(attestation_key, unsigned)):
        raise SupervisorAttestationError("remote response attestation verification failed")
    return run


def _decode_line(raw: bytes, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise SupervisorAttestationError(f"supervisor {label} framing is invalid")
    try:
        document = decode_json(raw[:-1])
    except ValueError as err:
        raise SupervisorAttestationError(f"supervisor {label} JSON is invalid") from err
    if not isinstance(document, dict):
        raise SupervisorAttestationError(f"supervisor {label} must be an object")
    return document


def _claims_from_documents(
    request: Mapping[str, object], response: Mapping[str, object]
) -> tuple[dict[str, Any], Mapping[str, object]]:
    envelope_fields = {"protocol", "request_id", "expected_host", "expected_worker_id", "payload"}
    response_fields = {"protocol", "request_id", "host", "worker_id", "payload"}
    if set(request) != envelope_fields or set(response) != response_fields:
        raise SupervisorAttestationError("supervisor exchange fields are invalid")
    if request["protocol"] != SSH_PROTOCOL or response["protocol"] != SSH_PROTOCOL:
        raise SupervisorAttestationError("supervisor exchange protocol is invalid")
    if response["request_id"] != request["request_id"]:
        raise SupervisorAttestationError("supervisor exchange request ID mismatch")
    if response["host"] != request["expected_host"] or response["worker_id"] != request["expected_worker_id"]:
        raise SupervisorAttestationError("supervisor exchange endpoint binding mismatch")
    request_payload = request["payload"]
    run = response["payload"]
    required = {
        "schema_version",
        "authorization_id",
        "action_plan",
        "timeout_seconds",
        "max_output_bytes",
        "exchange_nonce",
    }
    if not isinstance(request_payload, Mapping) or set(request_payload) != required or not isinstance(run, Mapping):
        raise SupervisorAttestationError("supervisor execution payload is invalid")
    claims = _build_claims(
        request_id=request["request_id"],
        exchange_nonce=request_payload["exchange_nonce"],
        host=request["expected_host"],
        worker_identity=request["expected_worker_id"],
        authorization_id=request_payload["authorization_id"],
        action_plan=request_payload["action_plan"],
        timeout_seconds=request_payload["timeout_seconds"],
        max_output_bytes=request_payload["max_output_bytes"],
        authorized_run=run,
    )
    return claims, run


def _build_claims(
    *,
    request_id: object,
    exchange_nonce: object,
    host: object,
    worker_identity: object,
    authorization_id: object,
    action_plan: object,
    timeout_seconds: object,
    max_output_bytes: object,
    authorized_run: Mapping[str, object],
) -> dict[str, Any]:
    validate_exchange_nonce(exchange_nonce)
    if not isinstance(action_plan, Mapping) or not isinstance(authorized_run, Mapping):
        raise SupervisorAttestationError("supervisor attestation binding document is invalid")
    if set(authorized_run) != {"schema_version", "result", "approval_receipt"}:
        raise SupervisorAttestationError("supervisor authorized run fields are invalid")
    result = authorized_run["result"]
    receipt = authorized_run["approval_receipt"]
    if not isinstance(result, Mapping) or not isinstance(receipt, Mapping):
        raise SupervisorAttestationError("supervisor authorized run payload is invalid")
    try:
        return {
            "request_id": request_id,
            "exchange_nonce": exchange_nonce,
            "host": host,
            "worker_identity": worker_identity,
            "authorization_id": authorization_id,
            "authorization_digest": receipt["authorization_digest"],
            "action_plan_id": action_plan["plan_id"],
            "plan_digest": action_plan["plan_digest"],
            "action_plan_digest": digest(dict(action_plan)),
            "engagement_id": action_plan["engagement_id"],
            "target": action_plan["target"],
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "result_digest": digest(dict(result)),
            "receipt_digest": digest(dict(receipt)),
        }
    except (KeyError, TypeError, ValueError) as err:
        raise SupervisorAttestationError("supervisor attestation binding fields are invalid") from err


def _mac(key: bytes, unsigned: Mapping[str, object]) -> str:
    return hmac.new(key, canonical(dict(unsigned)), hashlib.sha256).hexdigest()
