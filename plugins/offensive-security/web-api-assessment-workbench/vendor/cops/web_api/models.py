"""Data models for Web Application & API Inventory and Request Replay."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from cops.discovery.models import EvidenceProvenance
from cops.evidence.canonical import utc_now

from .sanitization import (
    SENSITIVE_FIELD_PATTERNS as SENSITIVE_FIELD_PATTERNS,
)
from .sanitization import (
    redact_credential_value as redact_credential_value,
)
from .sanitization import (
    redact_mapping as redact_mapping,
)
from .sanitization import (
    sanitize_body,
    sanitize_reference,
    sanitize_text,
    sanitize_tree,
)

_PROVENANCE_FIELDS = {"source_id", "source_type", "sha256", "timestamp", "path_or_uri", "raw_record_ref"}
_PROVENANCE_REQUIRED_FIELDS = _PROVENANCE_FIELDS - {"raw_record_ref"}
_OPAQUE_SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_OPAQUE_RECORD_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_SOURCE_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CREDENTIAL_TERM = re.compile(
    r"(?:secret|token|password|passwd|credential|api[-_]?key|authorization|cookie|session|jwt)", re.IGNORECASE
)
_INVALID_PROVENANCE = "inventory provenance record is invalid"
_INVALID_PUBLIC_METADATA = "inventory public metadata is invalid"
_INVALID_AUTHENTICATION = "inventory authentication mechanism is invalid"
_INVALID_SESSION_BINDING = "inventory endpoint session binding is invalid"
_OPAQUE_GRAPH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_HTTP_FIELD_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_AUTHORIZATION_HEADER = "Authorization"
_PUBLIC_REFERENCE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://|\b[^\s:@]+:[^\s@]+@[^\s]+)")
_RAW_HTTP_LABEL = re.compile(r"^Raw HTTP: [A-Z]+ /[^\s]*$")
_OPENAPI_SOURCE_LABEL = re.compile(r"^OpenAPI 3\.x / Swagger: [^/\\]+$")
MAX_WEB_API_DOCUMENT_BYTES = 8 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_DOCUMENT_TOO_LARGE = "web API document exceeds the byte limit"
_INVALID_DOCUMENT = "web API document is invalid"


def _valid_timestamp(value: str) -> bool:
    """Return whether value is a timezone-aware ISO 8601 timestamp."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def validate_inventory_provenance(record: EvidenceProvenance) -> EvidenceProvenance:
    """Validate one path-free, non-secret inventory provenance record."""
    if not isinstance(record, EvidenceProvenance):
        raise ValueError(_INVALID_PROVENANCE)
    values = (record.source_id, record.source_type, record.sha256, record.timestamp, record.path_or_uri)
    if not all(isinstance(value, str) for value in values):
        raise ValueError(_INVALID_PROVENANCE)
    if not _OPAQUE_SOURCE_ID.fullmatch(record.source_id) or _CREDENTIAL_TERM.search(record.source_id):
        raise ValueError(_INVALID_PROVENANCE)
    if not _SOURCE_TYPE.fullmatch(record.source_type) or _CREDENTIAL_TERM.search(record.source_type):
        raise ValueError(_INVALID_PROVENANCE)
    if not _SHA256.fullmatch(record.sha256):
        raise ValueError(_INVALID_PROVENANCE)
    if record.path_or_uri != f"sha256:{record.sha256}":
        raise ValueError(_INVALID_PROVENANCE)
    if not _valid_timestamp(record.timestamp):
        raise ValueError(_INVALID_PROVENANCE)
    if record.raw_record_ref is not None and (
        not isinstance(record.raw_record_ref, str)
        or not _OPAQUE_RECORD_REF.fullmatch(record.raw_record_ref)
        or _CREDENTIAL_TERM.search(record.raw_record_ref)
    ):
        raise ValueError(_INVALID_PROVENANCE)
    return record


def _inventory_provenance_from_dict(data: Any) -> EvidenceProvenance:
    """Construct validated provenance without echoing attacker-controlled values."""
    if not isinstance(data, dict) or set(data) - _PROVENANCE_FIELDS or not _PROVENANCE_REQUIRED_FIELDS <= set(data):
        raise ValueError(_INVALID_PROVENANCE)
    try:
        record = EvidenceProvenance(
            source_id=data["source_id"],
            source_type=data["source_type"],
            sha256=data["sha256"],
            timestamp=data["timestamp"],
            path_or_uri=data["path_or_uri"],
            raw_record_ref=data.get("raw_record_ref"),
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError(_INVALID_PROVENANCE) from None
    return validate_inventory_provenance(record)


def validate_inventory_public_label(value: Any) -> str:
    """Validate one bounded source-derived label without echoing it on failure."""
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 1024
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or (_PUBLIC_REFERENCE.search(value) and not _RAW_HTTP_LABEL.fullmatch(value))
        or (
            ("/" in value or "\\" in value)
            and not _RAW_HTTP_LABEL.fullmatch(value)
            and not _OPENAPI_SOURCE_LABEL.fullmatch(value)
        )
        or sanitize_text(value) != value
    ):
        raise ValueError(_INVALID_PUBLIC_METADATA)
    return value


def safe_inventory_public_label(value: Any, fallback: str) -> str:
    """Return a safe importer label, replacing untrusted references with a fixed fallback."""
    try:
        return validate_inventory_public_label(value)
    except (UnicodeError, ValueError):
        return validate_inventory_public_label(fallback)


def _validate_inventory_public_metadata(name: Any, imported_sources: Any) -> tuple[str, list[str]]:
    """Validate public source labels at inventory serialization boundaries."""
    if not isinstance(imported_sources, list):
        raise ValueError(_INVALID_PUBLIC_METADATA)
    try:
        safe_name = validate_inventory_public_label(name)
        safe_sources = [validate_inventory_public_label(value) for value in imported_sources]
    except (TypeError, UnicodeError, ValueError):
        raise ValueError(_INVALID_PUBLIC_METADATA) from None
    return safe_name, safe_sources


def load_bounded_json_document(path: Path | str) -> dict[str, Any]:
    """Load one JSON object through a finite max+1 binary read."""
    chunks: list[bytes] = []
    remaining = MAX_WEB_API_DOCUMENT_BYTES + 1
    try:
        with Path(path).open("rb") as stream:
            while remaining:
                chunk = stream.read(min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
    except (OSError, ValueError):
        raise ValueError(_INVALID_DOCUMENT) from None

    content = b"".join(chunks)
    if len(content) > MAX_WEB_API_DOCUMENT_BYTES:
        raise ValueError(_DOCUMENT_TOO_LARGE)
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(_INVALID_DOCUMENT) from None
    if not isinstance(document, dict):
        raise ValueError(_INVALID_DOCUMENT)
    return document


class HttpMethod(str, Enum):
    """Standard HTTP methods for API endpoints."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ApiProtocol(str, Enum):
    """Supported API communication protocols."""

    HTTP = "http"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"


class AuthType(str, Enum):
    """Authentication mechanism classification."""

    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "api_key"
    COOKIE = "cookie"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    CUSTOM = "custom"


@dataclass
class AuthenticationMechanism:
    """Authentication mechanism attached to an API endpoint or session."""

    auth_type: str = AuthType.NONE.value
    token_name: str = ""
    location: str = "header"  # header, query, cookie
    is_redacted: bool = True
    credential_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        validate_authentication_mechanism(self)
        return sanitize_tree(asdict(self))

    @classmethod
    def from_dict(cls, data: Any) -> AuthenticationMechanism:
        fields = {"auth_type", "token_name", "location", "is_redacted", "credential_hash"}
        if not isinstance(data, dict) or set(data) - fields:
            raise ValueError(_INVALID_AUTHENTICATION)
        mechanism = cls(
            auth_type=data.get("auth_type", AuthType.NONE.value),
            token_name=data.get("token_name", ""),
            location=data.get("location", "header"),
            is_redacted=data.get("is_redacted", True),
            credential_hash=data.get("credential_hash", ""),
        )
        return validate_authentication_mechanism(mechanism)


def _safe_authentication_token_name(value: Any) -> bool:
    """Return whether a public credential label is bounded and reference-free."""
    if not isinstance(value, str):
        return False
    try:
        return (
            len(value.encode("utf-8")) <= 256
            and not any(ord(character) < 33 or ord(character) == 127 for character in value)
            and not _PUBLIC_REFERENCE.search(value)
            and "/" not in value
            and "\\" not in value
            and sanitize_text(value) == value
        )
    except (UnicodeError, ValueError):
        return False


def validate_authentication_mechanism(mechanism: AuthenticationMechanism) -> AuthenticationMechanism:
    """Validate credential-free authentication metadata without echoing its values."""
    if not isinstance(mechanism, AuthenticationMechanism):
        raise ValueError(_INVALID_AUTHENTICATION)
    if (
        not isinstance(mechanism.auth_type, str)
        or mechanism.auth_type not in {item.value for item in AuthType}
        or not isinstance(mechanism.location, str)
        or mechanism.location not in {"header", "query", "cookie"}
        or not _safe_authentication_token_name(mechanism.token_name)
        or mechanism.is_redacted is not True
        or not isinstance(mechanism.credential_hash, str)
        or (mechanism.credential_hash != "" and not _SHA256.fullmatch(mechanism.credential_hash))
    ):
        raise ValueError(_INVALID_AUTHENTICATION)

    if mechanism.location == "header" and mechanism.token_name and not _HTTP_FIELD_NAME.fullmatch(mechanism.token_name):
        raise ValueError(_INVALID_AUTHENTICATION)

    if mechanism.auth_type == AuthType.NONE.value:
        valid_shape = mechanism.location == "header" and not mechanism.token_name and not mechanism.credential_hash
    elif mechanism.auth_type in {AuthType.BEARER.value, AuthType.BASIC.value, AuthType.OAUTH2.value}:
        valid_shape = mechanism.location == "header" and mechanism.token_name == _AUTHORIZATION_HEADER
    elif mechanism.auth_type == AuthType.API_KEY.value:
        valid_shape = mechanism.location in {"header", "query"} and bool(mechanism.token_name)
    elif mechanism.auth_type == AuthType.COOKIE.value:
        valid_shape = mechanism.location == "cookie" and bool(mechanism.token_name)
    elif mechanism.auth_type == AuthType.MTLS.value:
        valid_shape = mechanism.location == "header" and not mechanism.token_name and not mechanism.credential_hash
    else:
        valid_shape = bool(mechanism.token_name)
    if not valid_shape:
        raise ValueError(_INVALID_AUTHENTICATION)
    return mechanism


@dataclass
class HttpEndpoint:
    """Structured representation of a modeled HTTP/API endpoint."""

    endpoint_id: str
    method: str
    path: str
    host: str = ""
    protocol: str = ApiProtocol.HTTP.value
    summary: str = ""
    query_parameters: dict[str, str] = field(default_factory=dict)
    headers_schema: dict[str, str] = field(default_factory=dict)
    request_body_schema: dict[str, Any] = field(default_factory=dict)
    response_status_codes: list[int] = field(default_factory=list)
    auth_mechanisms: list[AuthenticationMechanism] = field(default_factory=list)
    session_id: str | None = None
    roles_allowed: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False
    graphql_operations: list[str] = field(default_factory=list)
    websocket_subprotocols: list[str] = field(default_factory=list)
    scheme: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["auth_mechanisms"] = [a.to_dict() for a in self.auth_mechanisms]
        d["headers_schema"] = redact_mapping(self.headers_schema)
        d["query_parameters"] = {key: redact_credential_value(value) for key, value in self.query_parameters.items()}
        d["request_body_schema"] = sanitize_tree(self.request_body_schema, sensitive_keys=True)
        return sanitize_tree(d)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HttpEndpoint:
        auths = [AuthenticationMechanism.from_dict(a) for a in data.get("auth_mechanisms", [])]
        return cls(
            endpoint_id=data["endpoint_id"],
            method=data["method"].upper(),
            path=data["path"],
            host=data.get("host", ""),
            protocol=data.get("protocol", ApiProtocol.HTTP.value),
            summary=data.get("summary", ""),
            query_parameters=dict(data.get("query_parameters", {})),
            headers_schema=dict(data.get("headers_schema", {})),
            request_body_schema=dict(data.get("request_body_schema", {})),
            response_status_codes=list(data.get("response_status_codes", [])),
            auth_mechanisms=auths,
            session_id=data.get("session_id"),
            roles_allowed=list(data.get("roles_allowed", [])),
            tags=list(data.get("tags", [])),
            deprecated=bool(data.get("deprecated", False)),
            graphql_operations=list(data.get("graphql_operations", [])),
            websocket_subprotocols=list(data.get("websocket_subprotocols", [])),
            scheme=data.get("scheme", ""),
        )


@dataclass
class UserRole:
    """Security role and authorization boundary context."""

    role_id: str
    role_name: str
    permissions: list[str] = field(default_factory=list)
    assigned_endpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_tree(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserRole:
        return cls(
            role_id=data["role_id"],
            role_name=data["role_name"],
            permissions=list(data.get("permissions", [])),
            assigned_endpoints=list(data.get("assigned_endpoints", [])),
        )


@dataclass
class SessionContext:
    """Isolated session context holding sanitized identity parameters."""

    session_id: str
    role_id: str
    auth_mechanism: AuthenticationMechanism = field(default_factory=AuthenticationMechanism)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    is_isolated: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["auth_mechanism"] = self.auth_mechanism.to_dict()
        d["headers"] = redact_mapping(self.headers)
        d["cookies"] = {key: redact_credential_value(value) for key, value in self.cookies.items()}
        return sanitize_tree(d)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionContext:
        auth = AuthenticationMechanism.from_dict(data.get("auth_mechanism", {}))
        return cls(
            session_id=data["session_id"],
            role_id=data["role_id"],
            auth_mechanism=auth,
            headers=dict(data.get("headers", {})),
            cookies=dict(data.get("cookies", {})),
            is_isolated=data.get("is_isolated", True),
        )


@dataclass
class UnsupportedFeature:
    """Record of an encountered protocol feature not supported by replay engine."""

    protocol: str
    feature_name: str
    reason: str
    affected_endpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_tree(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnsupportedFeature:
        return cls(
            protocol=data["protocol"],
            feature_name=data["feature_name"],
            reason=data["reason"],
            affected_endpoints=list(data.get("affected_endpoints", [])),
        )


@dataclass
class ApiInventory:
    """Aggregated web application and API inventory."""

    inventory_id: str
    name: str
    target_hosts: list[str] = field(default_factory=list)
    endpoints: list[HttpEndpoint] = field(default_factory=list)
    roles: list[UserRole] = field(default_factory=list)
    sessions: list[SessionContext] = field(default_factory=list)
    unsupported_features: list[UnsupportedFeature] = field(default_factory=list)
    imported_sources: list[str] = field(default_factory=list)
    credentials_redacted: bool = True
    created_at_utc: str = field(default_factory=utc_now)
    provenance: EvidenceProvenance | None = None
    provenance_sources: list[EvidenceProvenance] = field(default_factory=list)

    @staticmethod
    def _auth_identity(mechanism: AuthenticationMechanism) -> tuple[str, str, str, str]:
        name = mechanism.token_name.lower() if mechanism.location == "header" else mechanism.token_name
        return mechanism.auth_type, mechanism.location, name, mechanism.credential_hash

    def _validate_session_bindings(self) -> None:
        """Validate explicit endpoint-to-session references without exposing their values."""
        sessions: dict[str, SessionContext] = {}
        for session in self.sessions:
            if (
                not isinstance(session.session_id, str)
                or not _OPAQUE_GRAPH_ID.fullmatch(session.session_id)
                or session.session_id in sessions
            ):
                raise ValueError(_INVALID_SESSION_BINDING)
            sessions[session.session_id] = session

        for endpoint in self.endpoints:
            if endpoint.session_id is None:
                continue
            if not isinstance(endpoint.session_id, str) or not _OPAQUE_GRAPH_ID.fullmatch(endpoint.session_id):
                raise ValueError(_INVALID_SESSION_BINDING)
            session = sessions.get(endpoint.session_id)
            active = [item for item in endpoint.auth_mechanisms if item.auth_type != AuthType.NONE.value]
            if (
                session is None
                or len(active) != 1
                or self._auth_identity(active[0]) != self._auth_identity(session.auth_mechanism)
            ):
                raise ValueError(_INVALID_SESSION_BINDING)

    def _validate_authentication_metadata(self) -> None:
        """Validate every endpoint and session mechanism at the inventory boundary."""
        for endpoint in self.endpoints:
            if not isinstance(endpoint, HttpEndpoint) or not isinstance(endpoint.auth_mechanisms, list):
                raise ValueError(_INVALID_AUTHENTICATION)
            for mechanism in endpoint.auth_mechanisms:
                validate_authentication_mechanism(mechanism)
        for session in self.sessions:
            if not isinstance(session, SessionContext):
                raise ValueError(_INVALID_AUTHENTICATION)
            validate_authentication_mechanism(session.auth_mechanism)

    def to_dict(self) -> dict[str, Any]:
        self._validate_authentication_metadata()
        self._validate_session_bindings()
        name, imported_sources = _validate_inventory_public_metadata(self.name, self.imported_sources)
        if self.provenance is not None and self.provenance_sources:
            raise ValueError(_INVALID_PROVENANCE)
        provenance = validate_inventory_provenance(self.provenance).to_dict() if self.provenance else None
        provenance_sources = [validate_inventory_provenance(record).to_dict() for record in self.provenance_sources]
        return sanitize_tree(
            {
                "inventory_id": self.inventory_id,
                "name": name,
                "target_hosts": self.target_hosts,
                "endpoints": [e.to_dict() for e in self.endpoints],
                "roles": [r.to_dict() for r in self.roles],
                "sessions": [s.to_dict() for s in self.sessions],
                "unsupported_features": [u.to_dict() for u in self.unsupported_features],
                "imported_sources": imported_sources,
                "credentials_redacted": self.credentials_redacted,
                "created_at_utc": self.created_at_utc,
                "provenance": provenance,
                "provenance_sources": provenance_sources,
            }
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApiInventory:
        if not isinstance(data, dict):
            raise ValueError(_INVALID_DOCUMENT)
        name, imported_sources = _validate_inventory_public_metadata(data.get("name"), data.get("imported_sources", []))
        raw_provenance = data.get("provenance")
        raw_sources = data.get("provenance_sources", [])
        if raw_provenance is not None and raw_sources:
            raise ValueError(_INVALID_PROVENANCE)
        if not isinstance(raw_sources, list):
            raise ValueError(_INVALID_PROVENANCE)
        prov = _inventory_provenance_from_dict(raw_provenance) if raw_provenance is not None else None
        provenance_sources = [_inventory_provenance_from_dict(record) for record in raw_sources]
        endpoints = [HttpEndpoint.from_dict(e) for e in data.get("endpoints", [])]
        roles = [UserRole.from_dict(r) for r in data.get("roles", [])]
        sessions = [SessionContext.from_dict(s) for s in data.get("sessions", [])]
        unsupported = [UnsupportedFeature.from_dict(u) for u in data.get("unsupported_features", [])]
        inventory = cls(
            inventory_id=data["inventory_id"],
            name=name,
            target_hosts=list(data.get("target_hosts", [])),
            endpoints=endpoints,
            roles=roles,
            sessions=sessions,
            unsupported_features=unsupported,
            imported_sources=imported_sources,
            credentials_redacted=bool(data.get("credentials_redacted", True)),
            created_at_utc=data.get("created_at_utc", utc_now()),
            provenance=prov,
            provenance_sources=provenance_sources,
        )
        inventory._validate_authentication_metadata()
        inventory._validate_session_bindings()
        return inventory

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path | str) -> ApiInventory:
        return cls.from_dict(load_bounded_json_document(path))


@dataclass
class ReplayBudget:
    """Operational limits bounding API request replay."""

    max_requests: int = 50
    rate_limit_rps: float = 10.0
    timeout_seconds: float = 5.0
    max_redirect_hops: int = 3
    max_websocket_frames: int = 10

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplayBudget:
        return cls(
            max_requests=data.get("max_requests", 50),
            rate_limit_rps=data.get("rate_limit_rps", 10.0),
            timeout_seconds=data.get("timeout_seconds", 5.0),
            max_redirect_hops=data.get("max_redirect_hops", 3),
            max_websocket_frames=data.get("max_websocket_frames", 10),
        )


@dataclass
class ReplayRequest:
    """Single normalized request prepared for replay."""

    request_id: str
    endpoint_id: str
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    query_parameters: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    protocol: str = ApiProtocol.HTTP.value
    session_id: str | None = None
    role_id: str | None = None
    graphql_query: str | None = None
    websocket_messages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["url"] = sanitize_reference(self.url)
        data["headers"] = redact_mapping(self.headers)
        data["query_parameters"] = {key: redact_credential_value(value) for key, value in self.query_parameters.items()}
        data["body"] = sanitize_body(self.body)
        data["graphql_query"] = sanitize_body(self.graphql_query)
        data["websocket_messages"] = [sanitize_body(value) for value in self.websocket_messages]
        return sanitize_tree(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplayRequest:
        return cls(
            request_id=data["request_id"],
            endpoint_id=data["endpoint_id"],
            method=data["method"].upper(),
            url=data["url"],
            headers=dict(data.get("headers", {})),
            query_parameters=dict(data.get("query_parameters", {})),
            body=data.get("body"),
            protocol=data.get("protocol", ApiProtocol.HTTP.value),
            session_id=data.get("session_id"),
            role_id=data.get("role_id"),
            graphql_query=data.get("graphql_query"),
            websocket_messages=list(data.get("websocket_messages", [])),
        )


@dataclass
class ReplayResponse:
    """Observed response from request replay."""

    request_id: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    latency_ms: float = 0.0
    redirect_count: int = 0
    final_url: str = ""
    websocket_replies: list[str] = field(default_factory=list)
    error_message: str | None = None
    replay_success: bool = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["headers"] = redact_mapping(self.headers)
        data["body_excerpt"] = sanitize_body(self.body_excerpt)
        data["final_url"] = sanitize_reference(self.final_url)
        data["websocket_replies"] = [sanitize_body(value) for value in self.websocket_replies]
        return sanitize_tree(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplayResponse:
        return cls(
            request_id=data["request_id"],
            status_code=int(data.get("status_code", 0)),
            headers=dict(data.get("headers", {})),
            body_excerpt=data.get("body_excerpt", ""),
            latency_ms=float(data.get("latency_ms", 0.0)),
            redirect_count=int(data.get("redirect_count", 0)),
            final_url=data.get("final_url", ""),
            websocket_replies=list(data.get("websocket_replies", [])),
            error_message=data.get("error_message"),
            replay_success=bool(data.get("replay_success", True)),
        )


@dataclass
class ReplaySessionReport:
    """Complete report of an executed bounded request replay session."""

    session_id: str
    target_hosts: list[str]
    allowed_destinations: list[str]
    budget: ReplayBudget
    requests: list[ReplayRequest] = field(default_factory=list)
    responses: list[ReplayResponse] = field(default_factory=list)
    total_dispatched: int = 0
    total_successful: int = 0
    total_failed: int = 0
    destination_violations: int = 0
    created_at_utc: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_tree(
            {
                "session_id": self.session_id,
                "target_hosts": self.target_hosts,
                "allowed_destinations": self.allowed_destinations,
                "budget": self.budget.to_dict(),
                "requests": [r.to_dict() for r in self.requests],
                "responses": [r.to_dict() for r in self.responses],
                "total_dispatched": self.total_dispatched,
                "total_successful": self.total_successful,
                "total_failed": self.total_failed,
                "destination_violations": self.destination_violations,
                "created_at_utc": self.created_at_utc,
            }
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplaySessionReport:
        budget = ReplayBudget.from_dict(data.get("budget", {}))
        requests = [ReplayRequest.from_dict(r) for r in data.get("requests", [])]
        responses = [ReplayResponse.from_dict(r) for r in data.get("responses", [])]
        return cls(
            session_id=data["session_id"],
            target_hosts=list(data.get("target_hosts", [])),
            allowed_destinations=list(data.get("allowed_destinations", [])),
            budget=budget,
            requests=requests,
            responses=responses,
            total_dispatched=int(data.get("total_dispatched", len(requests))),
            total_successful=int(data.get("total_successful", 0)),
            total_failed=int(data.get("total_failed", 0)),
            destination_violations=int(data.get("destination_violations", 0)),
            created_at_utc=data.get("created_at_utc", utc_now()),
        )

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path | str) -> ReplaySessionReport:
        return cls.from_dict(load_bounded_json_document(path))
