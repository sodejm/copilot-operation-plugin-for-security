"""Signed, one-use operator-gateway dispatch authorization.

This module deliberately contains no provider client or credential handling.  A
broker can only carry a signed, bounded request envelope to its configured
operator gateway; the gateway independently verifies and consumes the grant.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from cops.evidence.canonical import EvidenceError, canonical, timestamp, utc_now

from .filesystem import SecureDirectoryError, open_directory_no_symlinks

GATEWAY_DISPATCH_SCHEMA = "cops.operator-gateway-dispatch/v2"
GATEWAY_DISPATCH_TRUST_SCHEMA = "cops.operator-gateway-dispatch-trust-store/v1"
GATEWAY_DISPATCH_ENVELOPE_SCHEMA = "cops.operator-gateway-envelope/v2"
GATEWAY_DISPATCH_ALGORITHM = "ed25519"
MAX_GATEWAY_DISPATCH_TTL_SECONDS = 300
_MAX_GRANT_BYTES = 16 * 1024
_MAX_TRUST_BYTES = 64 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")


class GatewayDispatchError(RuntimeError):
    """A gateway dispatch was denied without exposing request details."""


class GatewayDispatchValidationError(GatewayDispatchError):
    """A grant, request, or configured endpoint is invalid."""


class GatewayDispatchReplayError(GatewayDispatchError):
    """A dispatch identifier has already been consumed."""


class GatewayDispatchStoreError(GatewayDispatchError):
    """The durable replay store cannot be used safely."""


def _deny() -> GatewayDispatchValidationError:
    return GatewayDispatchValidationError("gateway dispatch authorization denied")


def _require_token(value: object) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise _deny()
    return value


def _require_hash(value: object) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise _deny()
    return value


def _require_spiffe(value: object) -> str:
    if not isinstance(value, str) or len(value) > 255 or not value.startswith("spiffe://"):
        raise _deny()
    parsed = urlsplit(value)
    if not parsed.netloc or parsed.query or parsed.fragment or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value):
        raise _deny()
    return value


def _require_request_target(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048 or value != value.strip():
        raise _deny()
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise _deny()
    if parsed.hostname is None or parsed.hostname != parsed.hostname.lower() or parsed.port is not None:
        raise _deny()
    canonical_target = f"https://{parsed.netloc}{parsed.path or '/'}"
    if canonical_target != value:
        raise _deny()
    return value


def _require_time(value: object) -> str:
    try:
        timestamp(value)
    except EvidenceError as err:
        raise _deny() from err
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class GatewayDispatchGrant:
    """A versioned signed grant bound to one approved provider request body."""

    schema_version: str
    dispatch_id: str
    authorization_id: str
    action_plan_id: str
    plan_digest: str
    worker_spiffe_id: str
    provider: str
    account_or_project_kind: str
    account_or_project: str
    region: str
    model: str
    gateway_endpoint_id: str
    request_target: str
    body_sha256: str
    body_bytes: int
    issued_at: str
    expires_at: str
    key_id: str
    algorithm: str
    signature: str = ""

    _FIELDS = (
        "schema_version", "dispatch_id", "authorization_id", "action_plan_id", "plan_digest",
        "worker_spiffe_id", "provider", "account_or_project_kind", "account_or_project", "region",
        "model", "gateway_endpoint_id", "request_target", "body_sha256", "body_bytes", "issued_at",
        "expires_at", "key_id", "algorithm", "signature",
    )

    def unsigned_dict(self) -> dict[str, object]:
        result = self.to_dict()
        result.pop("signature")
        return result

    def to_dict(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self._FIELDS}

    def validate(self, *, require_signature: bool = True) -> None:
        if self.schema_version != GATEWAY_DISPATCH_SCHEMA or self.algorithm != GATEWAY_DISPATCH_ALGORITHM:
            raise _deny()
        for field in (
            self.dispatch_id, self.authorization_id, self.action_plan_id, self.provider,
            self.account_or_project, self.region, self.model, self.gateway_endpoint_id, self.key_id,
        ):
            _require_token(field)
        if self.account_or_project_kind not in {"account", "project"}:
            raise _deny()
        _require_hash(self.plan_digest)
        _require_spiffe(self.worker_spiffe_id)
        _require_request_target(self.request_target)
        _require_hash(self.body_sha256)
        if type(self.body_bytes) is not int or self.body_bytes < 0 or self.body_bytes > 16 * 1024 * 1024:
            raise _deny()
        issued_at = timestamp(_require_time(self.issued_at))
        expires_at = timestamp(_require_time(self.expires_at))
        if expires_at <= issued_at or (expires_at - issued_at).total_seconds() > MAX_GATEWAY_DISPATCH_TTL_SECONDS:
            raise _deny()
        if require_signature:
            if not isinstance(self.signature, str) or not _SIGNATURE.fullmatch(self.signature):
                raise _deny()
        elif self.signature not in ("", None):
            raise _deny()

    @classmethod
    def from_dict(cls, value: object) -> "GatewayDispatchGrant":
        if not isinstance(value, dict) or set(value) != set(cls._FIELDS):
            raise _deny()
        try:
            grant = cls(**value)
        except (TypeError, ValueError) as err:
            raise _deny() from err
        grant.validate()
        return grant


def sign_gateway_dispatch(grant: GatewayDispatchGrant, private_key: Any) -> GatewayDispatchGrant:
    """Sign an otherwise unsigned grant with a caller-owned Ed25519 key."""
    grant.validate(require_signature=False)
    try:
        signature = private_key.sign(canonical(grant.unsigned_dict(), max_bytes=_MAX_GRANT_BYTES)).hex()
    except (AttributeError, TypeError, ValueError) as err:
        raise GatewayDispatchValidationError("gateway dispatch signing failed") from err
    signed = replace(grant, signature=signature)
    signed.validate()
    return signed


@dataclass(frozen=True)
class GatewayDispatchTrustStore:
    """Ed25519 public keys loaded only from an owner-protected local file."""

    keys: Mapping[str, bytes]

    def __post_init__(self) -> None:
        normalized: dict[str, bytes] = {}
        for key_id, key in self.keys.items():
            _require_token(key_id)
            if not isinstance(key, bytes) or len(key) != 32:
                raise _deny()
            normalized[key_id] = key
        if not normalized:
            raise _deny()
        object.__setattr__(self, "keys", MappingProxyType(normalized))

    @classmethod
    def from_file(cls, path: Path | str) -> "GatewayDispatchTrustStore":
        source = Path(path)
        descriptor = -1
        parent_fd = -1
        try:
            parent_fd = open_directory_no_symlinks(source.parent)
            descriptor = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise _deny()
            raw = os.read(descriptor, _MAX_TRUST_BYTES + 1)
            if len(raw) > _MAX_TRUST_BYTES:
                raise _deny()
        except (OSError, SecureDirectoryError) as err:
            raise GatewayDispatchValidationError("gateway dispatch trust store unavailable") from err
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent_fd >= 0:
                os.close(parent_fd)
        try:
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict) or set(parsed) != {"schema_version", "keys"} or parsed["schema_version"] != GATEWAY_DISPATCH_TRUST_SCHEMA:
                raise _deny()
            entries = parsed["keys"]
            if not isinstance(entries, list) or not entries:
                raise _deny()
            keys: dict[str, bytes] = {}
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"key_id", "algorithm", "public_key_hex"} or entry["algorithm"] != GATEWAY_DISPATCH_ALGORITHM:
                    raise _deny()
                key_id = _require_token(entry["key_id"])
                key_hex = entry["public_key_hex"]
                if key_id in keys or not isinstance(key_hex, str) or not _HASH.fullmatch(key_hex):
                    raise _deny()
                keys[key_id] = bytes.fromhex(key_hex)
            return cls(keys)
        except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as err:
            if isinstance(err, GatewayDispatchValidationError):
                raise
            raise _deny() from err

    def verify(self, grant: GatewayDispatchGrant) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            key = Ed25519PublicKey.from_public_bytes(self.keys[grant.key_id])
            key.verify(bytes.fromhex(grant.signature), canonical(grant.unsigned_dict(), max_bytes=_MAX_GRANT_BYTES))
        except (KeyError, ValueError, TypeError, Exception) as err:  # cryptography raises InvalidSignature
            # The public error must not distinguish unknown key, malformed signatures, or invalid signatures.
            raise _deny() from err


def verify_gateway_dispatch(
    grant: GatewayDispatchGrant,
    *,
    trust_store: GatewayDispatchTrustStore,
    current_time_iso: str | None = None,
) -> None:
    grant.validate()
    try:
        current = timestamp(current_time_iso if current_time_iso is not None else utc_now())
    except EvidenceError as err:
        raise _deny() from err
    if current < timestamp(grant.issued_at) or current > timestamp(grant.expires_at):
        raise _deny()
    trust_store.verify(grant)


def gateway_dispatch_descriptor_digest(grant: GatewayDispatchGrant) -> str:
    grant.validate()
    return hashlib.sha256(canonical(grant.unsigned_dict(), max_bytes=_MAX_GRANT_BYTES)).hexdigest()


class GatewayDispatchReplayStore:
    """SQLite-backed durable, fail-closed single-use dispatch consumption."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)

    def _prepare(self) -> None:
        parent_fd = -1
        try:
            parent_fd = open_directory_no_symlinks(self._path.parent, create=True, mode=0o700)
            try:
                fd = os.open(
                    self._path.name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                fd = os.open(self._path.name, os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                    raise GatewayDispatchStoreError("gateway dispatch replay store unavailable")
            finally:
                os.close(fd)
        except (OSError, SecureDirectoryError) as err:
            raise GatewayDispatchStoreError("gateway dispatch replay store unavailable") from err
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

    def consume(self, grant: GatewayDispatchGrant, *, current_time_iso: str | None = None) -> tuple[str, str]:
        grant.validate()
        self._prepare()
        consumed_at = current_time_iso if current_time_iso is not None else utc_now()
        try:
            timestamp(consumed_at)
            connection = sqlite3.connect(self._path, isolation_level=None, timeout=1.0)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS consumed_dispatches (dispatch_id TEXT PRIMARY KEY, descriptor_digest TEXT NOT NULL, consumed_at TEXT NOT NULL)"
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO consumed_dispatches (dispatch_id, descriptor_digest, consumed_at) VALUES (?, ?, ?)",
                    (grant.dispatch_id, gateway_dispatch_descriptor_digest(grant), consumed_at),
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as err:
                with __import__("contextlib").suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise GatewayDispatchReplayError("gateway dispatch authorization denied") from err
            finally:
                connection.close()
        except GatewayDispatchReplayError:
            raise
        except (sqlite3.Error, OSError, EvidenceError) as err:
            raise GatewayDispatchStoreError("gateway dispatch replay store unavailable") from err
        return gateway_dispatch_descriptor_digest(grant), consumed_at


@dataclass(frozen=True)
class GatewayDispatchEndpoint:
    """One configured provider scope behind the operator gateway."""

    gateway_endpoint_id: str
    gateway_identity: str
    provider: str
    account_or_project_kind: str
    account_or_project: str
    region: str
    model: str
    request_target: str

    def __post_init__(self) -> None:
        for value in (self.gateway_endpoint_id, self.provider, self.account_or_project, self.region, self.model):
            _require_token(value)
        _require_spiffe(self.gateway_identity)
        if self.account_or_project_kind not in {"account", "project"}:
            raise _deny()
        _require_request_target(self.request_target)


class GatewayDispatchTransportAuthorizer:
    """Verify an exact signed grant before the broker sends its envelope."""

    def __init__(self, *, trust_store: GatewayDispatchTrustStore, endpoints: Mapping[str, GatewayDispatchEndpoint]) -> None:
        if not isinstance(endpoints, Mapping) or not endpoints:
            raise _deny()
        normalized: dict[str, GatewayDispatchEndpoint] = {}
        for endpoint_id, endpoint in endpoints.items():
            if endpoint_id != endpoint.gateway_endpoint_id or not isinstance(endpoint, GatewayDispatchEndpoint):
                raise _deny()
            normalized[endpoint_id] = endpoint
        self._trust_store = trust_store
        self._endpoints = MappingProxyType(normalized)

    def verify_for_transport(
        self,
        *,
        grant: GatewayDispatchGrant,
        action_plan_id: str,
        plan_digest: str,
        presented_worker_spiffe_id: str,
        request_target: str,
        body: bytes,
        current_time_iso: str | None = None,
    ) -> GatewayDispatchEndpoint:
        if not isinstance(body, bytes):
            raise _deny()
        verify_gateway_dispatch(grant, trust_store=self._trust_store, current_time_iso=current_time_iso)
        if (
            action_plan_id != grant.action_plan_id
            or plan_digest != grant.plan_digest
            or presented_worker_spiffe_id != grant.worker_spiffe_id
            or request_target != grant.request_target
            or len(body) != grant.body_bytes
            or hashlib.sha256(body).hexdigest() != grant.body_sha256
        ):
            raise _deny()
        endpoint = self._endpoints.get(grant.gateway_endpoint_id)
        if endpoint is None or (
            endpoint.provider != grant.provider
            or endpoint.account_or_project_kind != grant.account_or_project_kind
            or endpoint.account_or_project != grant.account_or_project
            or endpoint.region != grant.region
            or endpoint.model != grant.model
            or endpoint.request_target != grant.request_target
        ):
            raise _deny()
        return endpoint


@dataclass(frozen=True)
class GatewayDispatchReceipt:
    gateway_receipt_id: str
    dispatch_id: str
    authorization_id: str
    action_plan_id: str
    plan_digest: str
    gateway_endpoint_id: str
    gateway_identity: str
    descriptor_digest: str
    body_sha256: str
    body_bytes: int
    decision: str
    consumed_at: str


@dataclass(frozen=True)
class GatewayDispatchInvocation:
    dispatch_id: str
    authorization_id: str
    action_plan_id: str
    plan_digest: str
    gateway_endpoint_id: str
    gateway_identity: str
    descriptor_digest: str
    body_sha256: str
    body_bytes: int


class GatewayDispatchEmulator:
    """An emulator boundary that verifies and consumes a grant before any handler."""

    def __init__(
        self,
        *,
        authorizer: GatewayDispatchTransportAuthorizer,
        replay_store: GatewayDispatchReplayStore,
        handler: Callable[[GatewayDispatchInvocation], None] | None = None,
    ) -> None:
        self._authorizer = authorizer
        self._replay_store = replay_store
        self._handler = handler

    def dispatch(
        self,
        *,
        grant: GatewayDispatchGrant,
        presented_worker_spiffe_id: str,
        request_target: str,
        body: bytes,
        current_time_iso: str | None = None,
    ) -> GatewayDispatchReceipt:
        endpoint = self._authorizer.verify_for_transport(
            grant=grant,
            action_plan_id=grant.action_plan_id,
            plan_digest=grant.plan_digest,
            presented_worker_spiffe_id=presented_worker_spiffe_id,
            request_target=request_target,
            body=body,
            current_time_iso=current_time_iso,
        )
        descriptor_digest, consumed_at = self._replay_store.consume(grant, current_time_iso=current_time_iso)
        invocation = GatewayDispatchInvocation(
            dispatch_id=grant.dispatch_id, authorization_id=grant.authorization_id,
            action_plan_id=grant.action_plan_id, plan_digest=grant.plan_digest,
            gateway_endpoint_id=endpoint.gateway_endpoint_id, gateway_identity=endpoint.gateway_identity,
            descriptor_digest=descriptor_digest, body_sha256=grant.body_sha256, body_bytes=grant.body_bytes,
        )
        if self._handler is not None:
            try:
                self._handler(invocation)
            except Exception as err:
                raise GatewayDispatchError("gateway dispatch failed after authorization consumption") from err
        receipt_id = hashlib.sha256(f"{descriptor_digest}:{consumed_at}".encode("ascii")).hexdigest()
        return GatewayDispatchReceipt(
            gateway_receipt_id=receipt_id, dispatch_id=grant.dispatch_id, authorization_id=grant.authorization_id,
            action_plan_id=grant.action_plan_id, plan_digest=grant.plan_digest,
            gateway_endpoint_id=endpoint.gateway_endpoint_id, gateway_identity=endpoint.gateway_identity,
            descriptor_digest=descriptor_digest, body_sha256=grant.body_sha256, body_bytes=grant.body_bytes,
            decision="accepted", consumed_at=consumed_at,
        )

    def dispatch_envelope(
        self, *, envelope: bytes, presented_worker_spiffe_id: str, current_time_iso: str | None = None
    ) -> GatewayDispatchReceipt:
        grant, body = decode_gateway_dispatch_envelope(envelope)
        return self.dispatch(
            grant=grant, presented_worker_spiffe_id=presented_worker_spiffe_id,
            request_target=grant.request_target, body=body, current_time_iso=current_time_iso,
        )


def encode_gateway_dispatch_envelope(*, grant: GatewayDispatchGrant, body: bytes) -> bytes:
    grant.validate()
    if not isinstance(body, bytes) or len(body) != grant.body_bytes or hashlib.sha256(body).hexdigest() != grant.body_sha256:
        raise _deny()
    return canonical(
        {"schema_version": GATEWAY_DISPATCH_ENVELOPE_SCHEMA, "grant": grant.to_dict(), "body_base64": base64.b64encode(body).decode("ascii"),
         "body_sha256": grant.body_sha256, "body_bytes": len(body)},
        max_bytes=16 * 1024 * 1024 + _MAX_GRANT_BYTES,
    )


def decode_gateway_dispatch_envelope(value: bytes) -> tuple[GatewayDispatchGrant, bytes]:
    if not isinstance(value, bytes) or len(value) > 16 * 1024 * 1024 + _MAX_GRANT_BYTES:
        raise _deny()
    try:
        parsed = json.loads(value.decode("utf-8"))
        if not isinstance(parsed, dict) or set(parsed) != {"schema_version", "grant", "body_base64", "body_sha256", "body_bytes"} or parsed["schema_version"] != GATEWAY_DISPATCH_ENVELOPE_SCHEMA:
            raise _deny()
        grant = GatewayDispatchGrant.from_dict(parsed["grant"])
        if not isinstance(parsed["body_base64"], str) or type(parsed["body_bytes"]) is not int or parsed["body_bytes"] < 0:
            raise _deny()
        body = base64.b64decode(parsed["body_base64"], validate=True)
        if len(body) != parsed["body_bytes"] or parsed["body_sha256"] != hashlib.sha256(body).hexdigest():
            raise _deny()
        if len(body) != grant.body_bytes or parsed["body_sha256"] != grant.body_sha256:
            raise _deny()
        return grant, body
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError, GatewayDispatchValidationError) as err:
        if isinstance(err, GatewayDispatchValidationError):
            raise
        raise _deny() from err
