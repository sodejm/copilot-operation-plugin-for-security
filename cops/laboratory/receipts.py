"""Verify independently signed operator laboratory observations."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cops.evidence.canonical import EvidenceError, canonical, timestamp
from cops.execution.filesystem import SecureDirectoryError, open_directory_no_symlinks

from .models import LaboratoryGateError, LaboratoryObservation, ResetError

_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
_PUBLIC_KEY = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RESET_SCHEMA = "cops.laboratory-reset-receipt/v2"
_CASE_SCHEMA = "cops.laboratory-case-observation/v2"
_ENVIRONMENT_SCHEMA = "cops.laboratory-environment-observation/v2"
_TRUST_SCHEMA = "cops.laboratory-observation-trust-store/v1"
_MAX_TRUST_BYTES = 64 * 1024


def operation_timestamp(value: str) -> datetime:
    if isinstance(value, str) and value.endswith("+00:00"):
        value = f"{value[:-6]}Z"
    return timestamp(value)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate laboratory trust-store field")
        result[key] = value
    return result


@dataclass(frozen=True)
class LaboratoryObservationTrustStore:
    """Owner-loaded public keys for an independent laboratory observation signer."""

    keys: Mapping[tuple[str, str], bytes]
    _file_verified: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))

    @property
    def is_verified(self) -> bool:
        return self._file_verified

    @classmethod
    def from_file(cls, path: Path | str) -> LaboratoryObservationTrustStore:
        source = Path(path)
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not source.is_absolute():
            raise LaboratoryGateError("laboratory observation trust-store path requires protected POSIX access")
        parent_fd = file_fd = -1
        try:
            parent_fd = open_directory_no_symlinks(source.parent)
            file_fd = os.open(
                source.name,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
            metadata = os.fstat(file_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise LaboratoryGateError("laboratory observation trust store must be an owner-only regular file")
            if metadata.st_size > _MAX_TRUST_BYTES:
                raise LaboratoryGateError("laboratory observation trust store exceeds the byte limit")
            chunks: list[bytes] = []
            remaining = _MAX_TRUST_BYTES + 1
            while remaining:
                chunk = os.read(file_fd, min(remaining, 8192))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                raise LaboratoryGateError("laboratory observation trust store exceeds the byte limit")
        except LaboratoryGateError:
            raise
        except (OSError, SecureDirectoryError) as err:
            raise LaboratoryGateError("laboratory observation trust store cannot be opened securely") from err
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
        try:
            document = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, ValueError) as err:
            raise LaboratoryGateError("laboratory observation trust store is invalid JSON") from err
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "keys"}
            or document["schema_version"] != _TRUST_SCHEMA
        ):
            raise LaboratoryGateError("laboratory observation trust store schema is invalid")
        entries = document["keys"]
        if not isinstance(entries, list) or not entries:
            raise LaboratoryGateError("laboratory observation trust store requires keys")
        keys: dict[tuple[str, str], bytes] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "worker_identity",
                "key_id",
                "algorithm",
                "public_key_hex",
            }:
                raise LaboratoryGateError("laboratory observation trust-store key is invalid")
            worker, key_id, algorithm, encoded = (
                entry[name] for name in ("worker_identity", "key_id", "algorithm", "public_key_hex")
            )
            if (
                not isinstance(worker, str)
                or _IDENTIFIER.fullmatch(worker) is None
                or not isinstance(key_id, str)
                or _IDENTIFIER.fullmatch(key_id) is None
                or algorithm != "ed25519"
                or not isinstance(encoded, str)
                or _PUBLIC_KEY.fullmatch(encoded) is None
                or (worker, key_id) in keys
            ):
                raise LaboratoryGateError("laboratory observation trust-store key is invalid")
            keys[(worker, key_id)] = bytes.fromhex(encoded)
        store = cls(keys)
        object.__setattr__(store, "_file_verified", True)
        return store

    def resolve(self, worker_identity: str, key_id: str) -> Ed25519PublicKey:
        if not self.is_verified or (worker_identity, key_id) not in self.keys:
            raise LaboratoryGateError("laboratory observation signing key is not trusted")
        return Ed25519PublicKey.from_public_bytes(self.keys[(worker_identity, key_id)])


@dataclass(frozen=True)
class LaboratoryResetReceipt:
    """Operator-signed completion of one challenged reset."""

    environment_id: str
    worker_identity: str
    strategy: str
    command_digest: str
    request_nonce: str
    completed_at: str
    succeeded: bool
    key_id: str
    signature: str
    algorithm: str = "ed25519"
    schema_version: str = _RESET_SCHEMA

    def unsigned(self) -> dict[str, object]:
        return {
            name: getattr(self, name)
            for name in (
                "schema_version",
                "algorithm",
                "environment_id",
                "worker_identity",
                "strategy",
                "command_digest",
                "request_nonce",
                "completed_at",
                "succeeded",
                "key_id",
            )
        }


@dataclass(frozen=True)
class LaboratoryCaseObservation:
    """Operator-signed case measurements bound to a challenged authorized result."""

    environment_id: str
    worker_identity: str
    authorization_id: str
    plan_digest: str
    result_id: str
    result_finished_at: str
    request_nonce: str
    observed_at: str
    canary_token_detected: bool
    control_blocked: bool
    key_id: str
    signature: str
    algorithm: str = "ed25519"
    schema_version: str = _CASE_SCHEMA

    def unsigned(self) -> dict[str, object]:
        return {
            name: getattr(self, name)
            for name in (
                "schema_version",
                "algorithm",
                "environment_id",
                "worker_identity",
                "authorization_id",
                "plan_digest",
                "result_id",
                "result_finished_at",
                "request_nonce",
                "observed_at",
                "canary_token_detected",
                "control_blocked",
                "key_id",
            )
        }


LaboratoryReceipt = LaboratoryResetReceipt | LaboratoryCaseObservation | LaboratoryObservation


def verify_receipt_signature(
    receipt: LaboratoryReceipt, *, trust_store: LaboratoryObservationTrustStore, worker_identity: str
) -> None:
    """Verify the full saved receipt without depending on current wall-clock time."""
    if not isinstance(trust_store, LaboratoryObservationTrustStore) or not trust_store.is_verified:
        raise LaboratoryGateError("a verified owner-provisioned laboratory observation trust store is required")
    if not isinstance(receipt, (LaboratoryResetReceipt, LaboratoryCaseObservation, LaboratoryObservation)):
        raise LaboratoryGateError("a typed operator-attested laboratory receipt is required")
    expected_schema = (
        _RESET_SCHEMA
        if isinstance(receipt, LaboratoryResetReceipt)
        else _CASE_SCHEMA
        if isinstance(receipt, LaboratoryCaseObservation)
        else _ENVIRONMENT_SCHEMA
    )
    if (
        receipt.schema_version != expected_schema
        or receipt.algorithm != "ed25519"
        or receipt.worker_identity != worker_identity
    ):
        raise LaboratoryGateError("laboratory receipt schema, algorithm, or worker identity mismatch")
    if not isinstance(receipt.signature, str) or _SIGNATURE.fullmatch(receipt.signature) is None:
        raise LaboratoryGateError("laboratory receipt signature is invalid")
    try:
        public_key = trust_store.resolve(worker_identity, receipt.key_id)
        public_key.verify(bytes.fromhex(receipt.signature), canonical(receipt.unsigned()))
    except (InvalidSignature, EvidenceError, TypeError, ValueError) as err:
        raise LaboratoryGateError("laboratory receipt signature or payload is invalid") from err


def verify_worker_receipt(
    receipt: LaboratoryReceipt,
    *,
    trust_store: LaboratoryObservationTrustStore,
    worker_identity: str,
    after: str | None = None,
) -> None:
    """Accept only a fresh exact-schema independently signed operator receipt."""
    verify_receipt_signature(receipt, trust_store=trust_store, worker_identity=worker_identity)
    time_value = receipt.completed_at if isinstance(receipt, LaboratoryResetReceipt) else receipt.observed_at
    try:
        observed_at = timestamp(time_value)
        lower_bound = operation_timestamp(after) if after is not None else None
    except EvidenceError as err:
        raise LaboratoryGateError("laboratory receipt timestamp is invalid") from err
    now = datetime.now(UTC)
    if observed_at < now - timedelta(minutes=2) or observed_at > now + timedelta(seconds=5):
        raise LaboratoryGateError("laboratory receipt is stale or future dated")
    if lower_bound is not None and observed_at <= lower_bound:
        raise LaboratoryGateError("laboratory receipt predates the operation")
    if isinstance(receipt, LaboratoryResetReceipt):
        if type(receipt.succeeded) is not bool or not receipt.succeeded:
            raise ResetError("operator reset did not succeed")
    elif isinstance(receipt, LaboratoryCaseObservation) and (
        type(receipt.canary_token_detected) is not bool or type(receipt.control_blocked) is not bool
    ):
        raise LaboratoryGateError("laboratory case observation is incomplete")
    elif isinstance(receipt, LaboratoryObservation) and (
        type(receipt.network_isolated) is not bool or type(receipt.egress_restricted) is not bool
    ):
        raise LaboratoryGateError("laboratory environment observation is incomplete")
