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
from dataclasses import field as dataclass_field
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from cops.evidence.canonical import EvidenceError, canonical, decode_json, timestamp, utc_now

from .filesystem import SecureDirectoryError, open_directory_no_symlinks

GATEWAY_DISPATCH_SCHEMA = "cops.operator-gateway-dispatch/v2"
GATEWAY_PRODUCTION_DISPATCH_SCHEMA = "cops.operator-gateway-dispatch/v3"
GATEWAY_DISPATCH_TRUST_SCHEMA = "cops.operator-gateway-dispatch-trust-store/v1"
GATEWAY_DISPATCH_ENVELOPE_SCHEMA = "cops.operator-gateway-envelope/v2"
GATEWAY_PRODUCTION_DISPATCH_ENVELOPE_SCHEMA = "cops.operator-gateway-envelope/v3"
GATEWAY_DISPATCH_ALGORITHM = "ed25519"
MAX_GATEWAY_DISPATCH_TTL_SECONDS = 300
MAX_GATEWAY_RESPONSE_BYTES = 1_048_576
_MAX_GRANT_BYTES = 16 * 1024
_MAX_TRUST_BYTES = 64 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
_OPAQUE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,127}\Z")
_PRODUCTION_VERSIONS = MappingProxyType(
    {
        "openai": "openai-responses/v1",
        "azure": "azure-openai-responses/v1",
        "aws": "bedrock-converse/v1",
        "gcp": "vertex-generate-content/v1",
    }
)


def _production_budget(output: object, response: object, elapsed: object, body: object) -> None:
    for value, maximum in (
        (output, 1_000_000),
        (response, MAX_GATEWAY_RESPONSE_BYTES),
        (elapsed, 30_000),
        (body, 262_144),
    ):
        if type(value) is not int or not 1 <= value <= maximum:
            raise _deny()


def _production_binding(value: object) -> None:
    if getattr(value, "execution_class", "production") != "production":
        raise _deny()
    if getattr(value, "provider", None) not in _PRODUCTION_VERSIONS or getattr(
        value, "transport_version", None
    ) != _PRODUCTION_VERSIONS.get(getattr(value, "provider", None)):
        raise _deny()
    for name in ("auth_profile_id", "credential_reference_id"):
        token = getattr(value, name, None)
        if not isinstance(token, str) or not _OPAQUE.fullmatch(token):
            raise _deny()
    for name in ("endpoint_policy_digest", "worker_evidence_digest"):
        _require_hash(getattr(value, name, None))


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
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        parsed = None
    if parsed is None:
        raise _deny()
    if (
        host is None
        or not host.isascii()
        or parsed.netloc != host
        or port is not None
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or parsed.query
        or parsed.fragment
        or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value)
    ):
        raise _deny()
    return value


def _require_request_target(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048 or value != value.strip():
        raise _deny()
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        parsed = None
    if parsed is None:
        raise _deny()
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise _deny()
    # urlsplit().hostname is lowercased, so comparing it to itself cannot
    # detect a noncanonical authority. Keep the signed target byte-exact.
    if host is None or parsed.netloc != host or port is not None or not host.isascii():
        raise _deny()
    canonical_target = f"https://{parsed.netloc}{parsed.path or '/'}"
    if canonical_target != value:
        raise _deny()
    return value


def _require_endpoint_origin(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048 or value != value.strip():
        raise _deny()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        parsed = None
    if parsed is None:
        raise _deny()
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or ":" in host
        or any(ord(character) > 127 for character in host)
    ):
        raise _deny()
    authority = host if port is None else f"{host}:{port}"
    canonical = f"https://{authority}"
    if parsed.netloc != authority or value != canonical:
        raise _deny()
    return value


def _require_gateway_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or len(value) > 2048
        or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value)
        or "?" in value
        or "#" in value
        or "\\" in value
        or "%" in value
        or any(segment in {".", ".."} for segment in value.split("/"))
    ):
        raise _deny()
    return value


def _require_time(value: object) -> str:
    invalid = False
    try:
        timestamp(value)
    except EvidenceError:
        invalid = True
    if invalid:
        raise _deny()
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
    execution_class: str | None = None
    auth_profile_id: str | None = None
    credential_reference_id: str | None = dataclass_field(default=None, repr=False)
    transport_version: str | None = None
    endpoint_policy_digest: str | None = None
    worker_evidence_digest: str | None = None
    max_output_tokens: int | None = None
    max_response_bytes: int | None = None
    max_elapsed_ms: int | None = None

    _FIELDS = (
        "schema_version",
        "dispatch_id",
        "authorization_id",
        "action_plan_id",
        "plan_digest",
        "worker_spiffe_id",
        "provider",
        "account_or_project_kind",
        "account_or_project",
        "region",
        "model",
        "gateway_endpoint_id",
        "request_target",
        "body_sha256",
        "body_bytes",
        "issued_at",
        "expires_at",
        "key_id",
        "algorithm",
        "signature",
    )
    _PRODUCTION_FIELDS = (
        "execution_class",
        "auth_profile_id",
        "credential_reference_id",
        "transport_version",
        "endpoint_policy_digest",
        "worker_evidence_digest",
        "max_output_tokens",
        "max_response_bytes",
        "max_elapsed_ms",
    )

    def unsigned_dict(self) -> dict[str, object]:
        result = self.to_dict()
        result.pop("signature")
        return result

    def to_dict(self) -> dict[str, object]:
        fields = self._FIELDS + (
            self._PRODUCTION_FIELDS if self.schema_version == GATEWAY_PRODUCTION_DISPATCH_SCHEMA else ()
        )
        return {field: getattr(self, field) for field in fields}

    def validate(self, *, require_signature: bool = True) -> None:
        production = self.schema_version == GATEWAY_PRODUCTION_DISPATCH_SCHEMA
        if (
            self.schema_version not in {GATEWAY_DISPATCH_SCHEMA, GATEWAY_PRODUCTION_DISPATCH_SCHEMA}
            or self.algorithm != GATEWAY_DISPATCH_ALGORITHM
        ):
            raise _deny()
        if production:
            _production_binding(self)
            _production_budget(self.max_output_tokens, self.max_response_bytes, self.max_elapsed_ms, self.body_bytes)
            if self.body_bytes < 2:
                raise _deny()
        elif any(getattr(self, field) is not None for field in self._PRODUCTION_FIELDS):
            raise _deny()
        for field in (
            self.dispatch_id,
            self.authorization_id,
            self.action_plan_id,
            self.provider,
            self.account_or_project,
            self.region,
            self.model,
            self.gateway_endpoint_id,
            self.key_id,
        ):
            _require_token(field)
        if self.account_or_project_kind not in (
            {"account", "tenant", "project", "subscription"} if production else {"account", "project"}
        ):
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
    def from_dict(cls, value: object) -> GatewayDispatchGrant:
        if not isinstance(value, dict):
            raise _deny()
        fields = cls._FIELDS + (
            cls._PRODUCTION_FIELDS if value.get("schema_version") == GATEWAY_PRODUCTION_DISPATCH_SCHEMA else ()
        )
        if set(value) != set(fields):
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
    def from_file(cls, path: Path | str) -> GatewayDispatchTrustStore:
        source = Path(path)
        descriptor = -1
        parent_fd = -1
        try:
            parent_fd = open_directory_no_symlinks(source.parent)
            descriptor = os.open(
                source.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd
            )
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
            if (
                not isinstance(parsed, dict)
                or set(parsed) != {"schema_version", "keys"}
                or parsed["schema_version"] != GATEWAY_DISPATCH_TRUST_SCHEMA
            ):
                raise _deny()
            entries = parsed["keys"]
            if not isinstance(entries, list) or not entries:
                raise _deny()
            keys: dict[str, bytes] = {}
            for entry in entries:
                if (
                    not isinstance(entry, dict)
                    or set(entry) != {"key_id", "algorithm", "public_key_hex"}
                    or entry["algorithm"] != GATEWAY_DISPATCH_ALGORITHM
                ):
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
        invalid = False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            key = Ed25519PublicKey.from_public_bytes(self.keys[grant.key_id])
            key.verify(bytes.fromhex(grant.signature), canonical(grant.unsigned_dict(), max_bytes=_MAX_GRANT_BYTES))
        except Exception:  # cryptography raises InvalidSignature
            # The public error must not distinguish unknown key, malformed signatures, or invalid signatures.
            invalid = True
        if invalid:
            raise _deny()


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
                    "CREATE TABLE IF NOT EXISTS consumed_dispatches (dispatch_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE, descriptor_digest TEXT NOT NULL, consumed_at TEXT NOT NULL)"
                )
                # Existing replay databases may predate the authorization column's
                # UNIQUE constraint. Enforce it on those databases as well.
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS consumed_dispatches_authorization_id_unique ON consumed_dispatches(authorization_id)"
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO consumed_dispatches (dispatch_id, authorization_id, descriptor_digest, consumed_at) VALUES (?, ?, ?, ?)",
                    (grant.dispatch_id, grant.authorization_id, gateway_dispatch_descriptor_digest(grant), consumed_at),
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
    endpoint_origin: str
    gateway_path: str
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
        _require_endpoint_origin(self.endpoint_origin)
        _require_gateway_path(self.gateway_path)
        if self.account_or_project_kind not in {"account", "project"}:
            raise _deny()
        _require_request_target(self.request_target)


@dataclass(frozen=True)
class GatewayProductionEndpoint(GatewayDispatchEndpoint):
    """Operator-provisioned production identity, credential scope, and ceilings."""

    auth_profile_id: str
    credential_reference_id: str = dataclass_field(repr=False)
    transport_version: str
    endpoint_policy_digest: str
    worker_evidence_digest: str
    max_output_tokens: int
    max_response_bytes: int
    max_elapsed_ms: int
    max_body_bytes: int = 262_144

    def __post_init__(self) -> None:
        for value in (self.gateway_endpoint_id, self.provider, self.account_or_project, self.region, self.model):
            _require_token(value)
        _require_spiffe(self.gateway_identity)
        _require_endpoint_origin(self.endpoint_origin)
        _require_gateway_path(self.gateway_path)
        _require_request_target(self.request_target)
        if self.account_or_project_kind not in {"account", "tenant", "project", "subscription"}:
            raise _deny()
        _production_binding(self)
        _production_budget(self.max_output_tokens, self.max_response_bytes, self.max_elapsed_ms, self.max_body_bytes)


class GatewayDispatchTransportAuthorizer:
    """Verify an exact signed grant before the broker sends its envelope."""

    def __init__(
        self, *, trust_store: GatewayDispatchTrustStore, endpoints: Mapping[str, GatewayDispatchEndpoint]
    ) -> None:
        if not isinstance(endpoints, Mapping) or not endpoints:
            raise _deny()
        normalized: dict[str, GatewayDispatchEndpoint] = {}
        for endpoint_id, endpoint in endpoints.items():
            if not isinstance(endpoint, GatewayDispatchEndpoint) or endpoint_id != endpoint.gateway_endpoint_id:
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
        endpoint_origin: str,
        gateway_path: str,
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
            or endpoint.endpoint_origin != endpoint_origin
            or endpoint.gateway_path != gateway_path
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
    response: GatewayDispatchResponse | None = dataclass_field(default=None, repr=False)


@dataclass(frozen=True)
class GatewayDispatchResponse:
    """Bounded JSON response, released only after grant consumption."""

    status_code: int
    media_type: str
    body: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.status_code) is not int
            or not 200 <= self.status_code <= 599
            or self.media_type != "application/json"
            or type(self.body) is not bytes
            or len(self.body) > 1_048_576
        ):
            raise GatewayDispatchError("gateway dispatch response is invalid")


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
    body: bytes = dataclass_field(repr=False)
    endpoint: GatewayDispatchEndpoint = dataclass_field(repr=False)


@dataclass(frozen=True)
class GatewayProductionInvocation(GatewayDispatchInvocation):
    auth_profile_id: str
    credential_reference_id: str = dataclass_field(repr=False)
    transport_version: str
    endpoint_policy_digest: str
    worker_evidence_digest: str
    max_output_tokens: int
    max_response_bytes: int
    max_elapsed_ms: int


class GatewayDispatchEmulator:
    """An emulator boundary that verifies and consumes a grant before any handler."""

    execution_class = "emulator"

    def __init__(
        self,
        *,
        authorizer: GatewayDispatchTransportAuthorizer,
        replay_store: GatewayDispatchReplayStore,
        action_plan_id: str,
        plan_digest: str,
        worker_spiffe_id: str,
        endpoint_origin: str,
        gateway_path: str,
        handler: Callable[[GatewayDispatchInvocation], GatewayDispatchResponse | None] | None = None,
    ) -> None:
        if getattr(handler, "production_only", False) and self.execution_class != "production":
            raise _deny()
        _require_token(action_plan_id)
        _require_hash(plan_digest)
        _require_spiffe(worker_spiffe_id)
        _require_endpoint_origin(endpoint_origin)
        _require_gateway_path(gateway_path)
        self._authorizer = authorizer
        self._replay_store = replay_store
        self._action_plan_id = action_plan_id
        self._plan_digest = plan_digest
        self._worker_spiffe_id = worker_spiffe_id
        self._endpoint_origin = endpoint_origin
        self._gateway_path = gateway_path
        self._handler = handler

    def preflight(
        self,
        *,
        grant: GatewayDispatchGrant,
        presented_worker_spiffe_id: str,
        request_target: str,
        body: bytes,
        current_time_iso: str | None = None,
    ) -> GatewayDispatchEndpoint:
        """Check the signed scope without consuming a grant or calling a handler."""
        if grant.schema_version != GATEWAY_DISPATCH_SCHEMA:
            raise _deny()
        return self._verify_endpoint(
            grant=grant,
            presented_worker_spiffe_id=presented_worker_spiffe_id,
            request_target=request_target,
            body=body,
            current_time_iso=current_time_iso,
        )

    def _verify_endpoint(
        self,
        *,
        grant: GatewayDispatchGrant,
        presented_worker_spiffe_id: str,
        request_target: str,
        body: bytes,
        current_time_iso: str | None,
    ) -> GatewayDispatchEndpoint:
        endpoint = self._authorizer.verify_for_transport(
            grant=grant,
            action_plan_id=self._action_plan_id,
            plan_digest=self._plan_digest,
            presented_worker_spiffe_id=presented_worker_spiffe_id,
            request_target=request_target,
            body=body,
            endpoint_origin=self._endpoint_origin,
            gateway_path=self._gateway_path,
            current_time_iso=current_time_iso,
        )
        if (
            presented_worker_spiffe_id != self._worker_spiffe_id
            or endpoint.endpoint_origin != self._endpoint_origin
            or endpoint.gateway_path != self._gateway_path
        ):
            raise _deny()
        return endpoint

    def _invocation(
        self,
        grant: GatewayDispatchGrant,
        endpoint: GatewayDispatchEndpoint,
        descriptor_digest: str,
        body: bytes,
    ) -> GatewayDispatchInvocation:
        return GatewayDispatchInvocation(
            dispatch_id=grant.dispatch_id,
            authorization_id=grant.authorization_id,
            action_plan_id=grant.action_plan_id,
            plan_digest=grant.plan_digest,
            gateway_endpoint_id=endpoint.gateway_endpoint_id,
            gateway_identity=endpoint.gateway_identity,
            descriptor_digest=descriptor_digest,
            body_sha256=grant.body_sha256,
            body_bytes=grant.body_bytes,
            body=body,
            endpoint=endpoint,
        )

    def dispatch(
        self,
        *,
        grant: GatewayDispatchGrant,
        presented_worker_spiffe_id: str,
        request_target: str,
        body: bytes,
        current_time_iso: str | None = None,
    ) -> GatewayDispatchReceipt:
        endpoint = self.preflight(
            grant=grant,
            presented_worker_spiffe_id=presented_worker_spiffe_id,
            request_target=request_target,
            body=body,
            current_time_iso=current_time_iso,
        )
        descriptor_digest, consumed_at = self._replay_store.consume(grant, current_time_iso=current_time_iso)
        invocation = self._invocation(grant, endpoint, descriptor_digest, body)
        response = None
        if self._handler is not None:
            failed = False
            try:
                response = self._handler(invocation)
                if response is not None and not isinstance(response, GatewayDispatchResponse):
                    raise GatewayDispatchError("gateway dispatch response is invalid")
            except Exception:
                # Handler failures may contain provider secrets or response text.
                # Raise after leaving the exception scope so the public error has
                # neither an explicit cause nor a stored implicit context.
                failed = True
            if failed:
                raise GatewayDispatchError("gateway dispatch failed after authorization consumption")
        receipt_id = hashlib.sha256(f"{descriptor_digest}:{consumed_at}".encode("ascii")).hexdigest()
        return GatewayDispatchReceipt(
            gateway_receipt_id=receipt_id,
            dispatch_id=grant.dispatch_id,
            authorization_id=grant.authorization_id,
            action_plan_id=grant.action_plan_id,
            plan_digest=grant.plan_digest,
            gateway_endpoint_id=endpoint.gateway_endpoint_id,
            gateway_identity=endpoint.gateway_identity,
            descriptor_digest=descriptor_digest,
            body_sha256=grant.body_sha256,
            body_bytes=grant.body_bytes,
            decision="accepted",
            consumed_at=consumed_at,
            response=response,
        )

    def dispatch_envelope(
        self, *, envelope: bytes, presented_worker_spiffe_id: str, current_time_iso: str | None = None
    ) -> GatewayDispatchReceipt:
        grant, body = decode_gateway_dispatch_envelope(envelope)
        return self.dispatch(
            grant=grant,
            presented_worker_spiffe_id=presented_worker_spiffe_id,
            request_target=grant.request_target,
            body=body,
            current_time_iso=current_time_iso,
        )


class GatewayProductionDispatcher(GatewayDispatchEmulator):
    """Consume a v3 grant before a gateway-owned typed credential can resolve."""

    execution_class = "production"

    def __init__(self, *, handler: object, **kwargs: object) -> None:
        from .gateway_credentials import GatewayProductionProviderHandler

        if not isinstance(handler, GatewayProductionProviderHandler):
            raise _deny()
        super().__init__(handler=handler, **kwargs)

    def preflight(
        self,
        *,
        grant: GatewayDispatchGrant,
        presented_worker_spiffe_id: str,
        request_target: str,
        body: bytes,
        current_time_iso: str | None = None,
    ) -> GatewayProductionEndpoint:
        # Emulator callers may inject a clock for deterministic fixtures, but a
        # production caller must never choose the instant used to verify grant
        # validity.  Reject the inherited test seam instead of silently
        # accepting a timestamp that could revive an expired authorization.
        if current_time_iso is not None:
            raise _deny()
        if not isinstance(grant, GatewayDispatchGrant) or grant.schema_version != GATEWAY_PRODUCTION_DISPATCH_SCHEMA:
            raise _deny()
        endpoint = self._verify_endpoint(
            grant=grant,
            presented_worker_spiffe_id=presented_worker_spiffe_id,
            request_target=request_target,
            body=body,
            current_time_iso=None,
        )
        if not isinstance(endpoint, GatewayProductionEndpoint):
            raise _deny()
        for name in (
            "auth_profile_id",
            "credential_reference_id",
            "transport_version",
            "endpoint_policy_digest",
            "worker_evidence_digest",
        ):
            if getattr(grant, name) != getattr(endpoint, name):
                raise _deny()
        for name in ("max_output_tokens", "max_response_bytes", "max_elapsed_ms"):
            if getattr(grant, name) != getattr(endpoint, name):
                raise _deny()
        if len(body) > endpoint.max_body_bytes:
            raise _deny()
        # The provider receives only this restricted, no-tool request grammar.
        _validate_production_body(endpoint, grant, body)
        self._handler.preflight(endpoint, grant)
        return endpoint

    def _invocation(
        self,
        grant: GatewayDispatchGrant,
        endpoint: GatewayDispatchEndpoint,
        descriptor_digest: str,
        body: bytes,
    ) -> GatewayProductionInvocation:
        values = vars(super()._invocation(grant, endpoint, descriptor_digest, body))
        return GatewayProductionInvocation(
            **values,
            **{
                name: getattr(grant, name)
                for name in GatewayDispatchGrant._PRODUCTION_FIELDS
                if name != "execution_class"
            },
        )


def _validate_production_body(endpoint: GatewayProductionEndpoint, grant: GatewayDispatchGrant, body: bytes) -> None:
    invalid = False
    try:
        value = decode_json(body, max_bytes=262_144, max_depth=16)
        if not isinstance(value, dict):
            raise _deny()
        if endpoint.provider in {"openai", "azure"}:
            if set(value) != {"model", "input", "max_output_tokens", "store", "stream"}:
                raise _deny()
            if value["model"] != endpoint.model or value["store"] is not False or value["stream"] is not False:
                raise _deny()
            messages, limit = value["input"], value["max_output_tokens"]
            if not isinstance(messages, str) or not messages.strip():
                raise _deny()
        elif endpoint.provider == "aws":
            if set(value) != {"messages", "inferenceConfig"} or not isinstance(value["inferenceConfig"], dict):
                raise _deny()
            if set(value["inferenceConfig"]) != {"maxTokens"}:
                raise _deny()
            limit = value["inferenceConfig"]["maxTokens"]
            messages = value["messages"]
            if not isinstance(messages, list) or len(messages) != 1 or set(messages[0]) != {"role", "content"}:
                raise _deny()
            if messages[0]["role"] != "user":
                raise _deny()
            content = messages[0]["content"]
            if (
                not isinstance(content, list)
                or len(content) != 1
                or set(content[0]) != {"text"}
                or not isinstance(content[0]["text"], str)
                or not content[0]["text"].strip()
            ):
                raise _deny()
        else:
            if set(value) != {"contents", "generationConfig"} or not isinstance(value["generationConfig"], dict):
                raise _deny()
            if set(value["generationConfig"]) != {"maxOutputTokens"}:
                raise _deny()
            limit = value["generationConfig"]["maxOutputTokens"]
            messages = value["contents"]
            if not isinstance(messages, list) or len(messages) != 1 or set(messages[0]) != {"role", "parts"}:
                raise _deny()
            if messages[0]["role"] != "user":
                raise _deny()
            content = messages[0]["parts"]
            if (
                not isinstance(content, list)
                or len(content) != 1
                or set(content[0]) != {"text"}
                or not isinstance(content[0]["text"], str)
                or not content[0]["text"].strip()
            ):
                raise _deny()
        if type(limit) is not int or limit != grant.max_output_tokens:
            raise _deny()
    except Exception:
        invalid = True
    if invalid:
        raise _deny()


def encode_gateway_dispatch_envelope(*, grant: GatewayDispatchGrant, body: bytes) -> bytes:
    grant.validate()
    if (
        not isinstance(body, bytes)
        or len(body) != grant.body_bytes
        or hashlib.sha256(body).hexdigest() != grant.body_sha256
    ):
        raise _deny()
    return canonical(
        {
            "schema_version": GATEWAY_PRODUCTION_DISPATCH_ENVELOPE_SCHEMA
            if grant.schema_version == GATEWAY_PRODUCTION_DISPATCH_SCHEMA
            else GATEWAY_DISPATCH_ENVELOPE_SCHEMA,
            "grant": grant.to_dict(),
            "body_base64": base64.b64encode(body).decode("ascii"),
            "body_sha256": grant.body_sha256,
            "body_bytes": len(body),
        },
        max_bytes=16 * 1024 * 1024 + _MAX_GRANT_BYTES,
    )


def decode_gateway_dispatch_envelope(value: bytes) -> tuple[GatewayDispatchGrant, bytes]:
    if not isinstance(value, bytes) or len(value) > 16 * 1024 * 1024 + _MAX_GRANT_BYTES:
        raise _deny()
    try:
        parsed = decode_json(value, max_bytes=16 * 1024 * 1024 + _MAX_GRANT_BYTES, max_depth=20)
        if (
            not isinstance(parsed, dict)
            or set(parsed) != {"schema_version", "grant", "body_base64", "body_sha256", "body_bytes"}
            or parsed["schema_version"]
            not in {GATEWAY_DISPATCH_ENVELOPE_SCHEMA, GATEWAY_PRODUCTION_DISPATCH_ENVELOPE_SCHEMA}
        ):
            raise _deny()
        grant = GatewayDispatchGrant.from_dict(parsed["grant"])
        if (parsed["schema_version"] == GATEWAY_PRODUCTION_DISPATCH_ENVELOPE_SCHEMA) != (
            grant.schema_version == GATEWAY_PRODUCTION_DISPATCH_SCHEMA
        ):
            raise _deny()
        if (
            not isinstance(parsed["body_base64"], str)
            or type(parsed["body_bytes"]) is not int
            or parsed["body_bytes"] < 0
        ):
            raise _deny()
        body = base64.b64decode(parsed["body_base64"], validate=True)
        if len(body) != parsed["body_bytes"] or parsed["body_sha256"] != hashlib.sha256(body).hexdigest():
            raise _deny()
        if len(body) != grant.body_bytes or parsed["body_sha256"] != grant.body_sha256:
            raise _deny()
        return grant, body
    except (UnicodeError, ValueError, TypeError, EvidenceError, json.JSONDecodeError, GatewayDispatchValidationError):
        invalid = True
    if invalid:
        raise _deny()
