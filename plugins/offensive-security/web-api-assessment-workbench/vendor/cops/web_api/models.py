"""Data models for Web Application & API Inventory and Request Replay."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
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
    sanitize_tree,
)


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
        return sanitize_tree(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthenticationMechanism:
        return cls(
            auth_type=data.get("auth_type", AuthType.NONE.value),
            token_name=data.get("token_name", ""),
            location=data.get("location", "header"),
            is_redacted=bool(data.get("is_redacted", True)),
            credential_hash=data.get("credential_hash", ""),
        )


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
    roles_allowed: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False
    graphql_operations: list[str] = field(default_factory=list)
    websocket_subprotocols: list[str] = field(default_factory=list)

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
            roles_allowed=list(data.get("roles_allowed", [])),
            tags=list(data.get("tags", [])),
            deprecated=bool(data.get("deprecated", False)),
            graphql_operations=list(data.get("graphql_operations", [])),
            websocket_subprotocols=list(data.get("websocket_subprotocols", [])),
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
            is_isolated=bool(data.get("is_isolated", True)),
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

    def to_dict(self) -> dict[str, Any]:
        return sanitize_tree(
            {
                "inventory_id": self.inventory_id,
                "name": self.name,
                "target_hosts": self.target_hosts,
                "endpoints": [e.to_dict() for e in self.endpoints],
                "roles": [r.to_dict() for r in self.roles],
                "sessions": [s.to_dict() for s in self.sessions],
                "unsupported_features": [u.to_dict() for u in self.unsupported_features],
                "imported_sources": self.imported_sources,
                "credentials_redacted": self.credentials_redacted,
                "created_at_utc": self.created_at_utc,
                "provenance": self.provenance.to_dict() if self.provenance else None,
            }
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApiInventory:
        endpoints = [HttpEndpoint.from_dict(e) for e in data.get("endpoints", [])]
        roles = [UserRole.from_dict(r) for r in data.get("roles", [])]
        sessions = [SessionContext.from_dict(s) for s in data.get("sessions", [])]
        unsupported = [UnsupportedFeature.from_dict(u) for u in data.get("unsupported_features", [])]
        prov = EvidenceProvenance.from_dict(data["provenance"]) if data.get("provenance") else None
        return cls(
            inventory_id=data["inventory_id"],
            name=data["name"],
            target_hosts=list(data.get("target_hosts", [])),
            endpoints=endpoints,
            roles=roles,
            sessions=sessions,
            unsupported_features=unsupported,
            imported_sources=list(data.get("imported_sources", [])),
            credentials_redacted=bool(data.get("credentials_redacted", True)),
            created_at_utc=data.get("created_at_utc", utc_now()),
            provenance=prov,
        )

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path | str) -> ApiInventory:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)


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
            max_requests=int(data.get("max_requests", 50)),
            rate_limit_rps=float(data.get("rate_limit_rps", 10.0)),
            timeout_seconds=float(data.get("timeout_seconds", 5.0)),
            max_redirect_hops=int(data.get("max_redirect_hops", 3)),
            max_websocket_frames=int(data.get("max_websocket_frames", 10)),
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
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)
