"""Importers and parsers for HTTP traffic, OpenAPI, Postman, and raw HTTP descriptions."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from cops.discovery.models import EvidenceProvenance
from cops.evidence.canonical import utc_now

from .models import (
    SENSITIVE_FIELD_PATTERNS,
    ApiInventory,
    ApiProtocol,
    AuthenticationMechanism,
    AuthType,
    HttpEndpoint,
    SessionContext,
    UnsupportedFeature,
    UserRole,
    redact_credential_value,
    safe_inventory_public_label,
    validate_inventory_provenance,
)
from .sanitization import authority, sanitize_text


class ImporterError(Exception):
    """Raised when an import input format is malformed or invalid."""


_UNSAFE_LOCATION_CHARACTER = re.compile(r"[\\\s\x00-\x1f\x7f]")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_TRANSPORT_CONTROLLED_HEADERS = {
    "connection",
    "content-length",
    "expect",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
MAX_IMPORT_BYTES = 8 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_INPUT_TOO_LARGE = "API import input exceeds the byte limit"
_AUTHORIZATION_HEADER = "Authorization"


def _has_unsafe_location_character(value: str) -> bool:
    """Return whether parsing could normalize or reinterpret a location value."""
    return _UNSAFE_LOCATION_CHARACTER.search(value) is not None


def _is_safe_auth_header_name(value: str) -> bool:
    """Return whether a synthesized credential can safely use this header."""
    return _HEADER_NAME.fullmatch(value) is not None and value.lower() not in _TRANSPORT_CONTROLLED_HEADERS


def _sanitize_headers(
    headers: list[dict[str, Any]] | dict[str, Any],
) -> tuple[dict[str, str], list[AuthenticationMechanism]]:
    """Sanitize headers, redact credential values, and extract authentication mechanisms."""
    clean_headers: dict[str, str] = {}
    auth_mechs: list[AuthenticationMechanism] = []

    header_items = (
        headers.items()
        if isinstance(headers, dict)
        else [(h.get("name", h.get("key", "")), h.get("value", "")) for h in headers]
    )

    for k, v in header_items:
        k_str = str(k).strip()
        v_str = str(v).strip()
        k_lower = k_str.lower()

        if k_lower == "authorization":
            # Extract Bearer or Basic
            parts = v_str.split(" ", 1)
            scheme = parts[0].lower() if parts else "bearer"
            auth_type = (
                AuthType.BEARER.value
                if scheme == "bearer"
                else (AuthType.BASIC.value if scheme == "basic" else AuthType.CUSTOM.value)
            )
            c_hash = hashlib.sha256(v_str.encode("utf-8")).hexdigest()
            auth_mechs.append(
                AuthenticationMechanism(
                    auth_type=auth_type,
                    token_name=_AUTHORIZATION_HEADER,
                    location="header",
                    is_redacted=True,
                    credential_hash=c_hash,
                )
            )
            clean_headers[k_str] = redact_credential_value(v_str)
        elif "cookie" in k_lower:
            c_hash = hashlib.sha256(v_str.encode("utf-8")).hexdigest()
            auth_mechs.append(
                AuthenticationMechanism(
                    auth_type=AuthType.COOKIE.value,
                    token_name=k_str,
                    location="cookie",
                    is_redacted=True,
                    credential_hash=c_hash,
                )
            )
            clean_headers[k_str] = redact_credential_value(v_str)
        elif SENSITIVE_FIELD_PATTERNS.search(k_lower):
            c_hash = hashlib.sha256(v_str.encode("utf-8")).hexdigest()
            auth_mechs.append(
                AuthenticationMechanism(
                    auth_type=AuthType.API_KEY.value,
                    token_name=k_str,
                    location="header",
                    is_redacted=True,
                    credential_hash=c_hash,
                )
            )
            clean_headers[k_str] = redact_credential_value(v_str)
        else:
            clean_headers[k_str] = sanitize_text(v_str)

    return clean_headers, auth_mechs


def _sanitize_query(
    query_dict: dict[str, str] | list[dict[str, str]],
) -> tuple[dict[str, str], list[AuthenticationMechanism]]:
    """Sanitize query parameters and redact sensitive tokens."""
    clean_params: dict[str, str] = {}
    auth_mechs: list[AuthenticationMechanism] = []

    items = (
        query_dict.items()
        if isinstance(query_dict, dict)
        else [(q.get("name", q.get("key", "")), q.get("value", "")) for q in query_dict]
    )

    for k, v in items:
        k_str = str(k).strip()
        v_str = str(v).strip()
        if SENSITIVE_FIELD_PATTERNS.search(k_str):
            c_hash = hashlib.sha256(v_str.encode("utf-8")).hexdigest()
            auth_mechs.append(
                AuthenticationMechanism(
                    auth_type=AuthType.API_KEY.value,
                    token_name=k_str,
                    location="query",
                    is_redacted=True,
                    credential_hash=c_hash,
                )
            )
            clean_params[k_str] = redact_credential_value(v_str)
        else:
            clean_params[k_str] = redact_credential_value(v_str)

    return clean_params, auth_mechs


def _bounded_bytes(chunks: Any) -> bytes:
    """Collect at most max+1 bytes and reject oversized input without echoing it."""
    content = bytearray()
    for chunk in chunks:
        content.extend(chunk[: MAX_IMPORT_BYTES + 1 - len(content)])
        if len(content) > MAX_IMPORT_BYTES:
            raise ImporterError(_INPUT_TOO_LARGE)
    return bytes(content)


def _read_bounded_path(path: Path) -> bytes:
    """Read a path incrementally with a finite max+1 byte ceiling."""
    try:
        with path.open("rb") as stream:
            content = bytearray()
            while len(content) <= MAX_IMPORT_BYTES:
                remaining = MAX_IMPORT_BYTES + 1 - len(content)
                chunk = stream.read(min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) > MAX_IMPORT_BYTES:
                raise ImporterError(_INPUT_TOO_LARGE)
            return bytes(content)
    except ImporterError:
        raise
    except OSError:
        raise ImporterError("Unable to read API import input") from None


def _bounded_text_bytes(value: str) -> bytes:
    """Encode inline text incrementally so its UTF-8 form obeys the same bound."""
    try:
        return _bounded_bytes(
            value[offset : offset + _READ_CHUNK_BYTES].encode("utf-8")
            for offset in range(0, len(value), _READ_CHUNK_BYTES)
        )
    except UnicodeError:
        raise ImporterError("Unable to read API import input") from None


def _encoded_text_chunks(values: Any) -> Any:
    """Yield bounded UTF-8 chunks without materializing a large encoded value."""
    for value in values:
        for offset in range(0, len(value), _READ_CHUNK_BYTES):
            yield value[offset : offset + _READ_CHUNK_BYTES].encode("utf-8")


def _input_bytes(data: dict[str, Any] | str | Path) -> bytes:
    """Read at most the documented limit, retaining exact accepted raw bytes."""
    try:
        if isinstance(data, dict):
            encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False)
            return _bounded_bytes(_encoded_text_chunks(encoder.iterencode(data)))
        if isinstance(data, Path):
            return _read_bounded_path(data)
        if isinstance(data, str):
            # JSON and HTTP payloads must never be probed as filesystem paths.
            if len(data) < 240 and not any(char in data for char in '\r\n{["'):
                candidate = Path(data)
                if candidate.is_file():
                    return _read_bounded_path(candidate)
            return _bounded_text_bytes(data)
    except ImporterError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        raise ImporterError("Unable to read API import input") from None
    raise ImporterError("Unsupported API import input type")


def _load_json_data(data: dict[str, Any] | str | Path) -> tuple[dict[str, Any], bytes]:
    content = _input_bytes(data)
    try:
        result = json.loads(content)
    except (ValueError, UnicodeError, RecursionError):
        raise ImporterError("Invalid API import JSON") from None
    if not isinstance(result, dict):
        raise ImporterError("API import JSON must be an object")
    return result, content


def _provenance(
    content: bytes, kind: str, source_id: str | None, supplied: EvidenceProvenance | None
) -> EvidenceProvenance:
    content_hash = hashlib.sha256(content).hexdigest()
    if supplied is not None:
        try:
            validate_inventory_provenance(supplied)
        except ValueError:
            raise ImporterError("API import provenance is invalid") from None
        if supplied.sha256 != content_hash:
            raise ImporterError("API import provenance does not match input content")
    record = EvidenceProvenance(
        source_id=source_id or (supplied.source_id if supplied else f"source-{content_hash[:12]}"),
        source_type=kind,
        sha256=content_hash,
        timestamp=supplied.timestamp if supplied else utc_now(),
        path_or_uri=f"sha256:{content_hash}",
        raw_record_ref=supplied.raw_record_ref if supplied else None,
    )
    try:
        return validate_inventory_provenance(record)
    except ValueError:
        raise ImporterError("API import provenance is invalid") from None


def _import_authority(url: str) -> str:
    try:
        return authority(url)
    except ValueError:
        raise ImporterError("Invalid API import authority") from None


def _join_api_paths(prefix: str, operation_path: str) -> str:
    """Join paths by normalizing only their shared boundary separator."""
    if prefix in ("", "/"):
        return operation_path
    return f"{prefix[:-1] if prefix.endswith('/') else prefix}{operation_path}"


def _openapi_server_location(server: Any) -> tuple[str, str]:
    """Resolve and validate one representable OpenAPI 3 server."""
    if not isinstance(server, dict) or not isinstance(server.get("url"), str) or not server["url"]:
        raise ImporterError("OpenAPI server is malformed")
    if _has_unsafe_location_character(server["url"]):
        raise ImporterError("OpenAPI server cannot be represented safely")

    variables = server.get("variables", {})
    if not isinstance(variables, dict):
        raise ImporterError("OpenAPI server is malformed")

    def replace_variable(match: re.Match[str]) -> str:
        definition = variables.get(match.group(1))
        if not isinstance(definition, dict) or not isinstance(definition.get("default"), str):
            raise ImporterError("OpenAPI server contains an unresolved variable")
        return definition["default"]

    resolved_url = re.sub(r"\{([^{}]+)\}", replace_variable, server["url"])
    if "{" in resolved_url or "}" in resolved_url:
        raise ImporterError("OpenAPI server contains an unresolved variable")
    if _has_unsafe_location_character(resolved_url):
        raise ImporterError("OpenAPI server cannot be represented safely")

    try:
        parsed = urlparse(resolved_url)
        parsed_hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        raise ImporterError("OpenAPI server cannot be represented safely") from None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or not parsed_hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ImporterError("OpenAPI server cannot be represented safely")
    return _import_authority(resolved_url), parsed.path or "/"


def _selected_openapi_server(
    raw_obj: dict[str, Any],
    path_item: dict[str, Any],
    operation: dict[str, Any],
) -> tuple[str, str, bool]:
    """Return the narrowest applicable OpenAPI server and alternative flag."""
    selected: Any = None
    for owner in (operation, path_item, raw_obj):
        if "servers" in owner:
            selected = owner["servers"]
            break
    if selected is None:
        return "api.target.local", "/", False
    if not isinstance(selected, list) or not selected:
        raise ImporterError("OpenAPI server declaration is malformed")
    host, prefix = _openapi_server_location(selected[0])
    return host, prefix, len(selected) > 1


def _openapi_parameters(path_item: dict[str, Any], operation: dict[str, Any]) -> list[dict[str, Any]]:
    """Inherit path parameters, with operation overrides by name and location."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for owner in (path_item, operation):
        parameters = owner.get("parameters", [])
        if not isinstance(parameters, list):
            raise ImporterError("OpenAPI parameter declaration cannot be represented safely")
        seen: set[tuple[str, str]] = set()
        for parameter in parameters:
            if (
                not isinstance(parameter, dict)
                or "$ref" in parameter
                or not isinstance(parameter.get("name"), str)
                or not parameter["name"]
                or not isinstance(parameter.get("in"), str)
                or not parameter["in"]
            ):
                raise ImporterError("OpenAPI parameter declaration cannot be represented safely")
            key = (parameter["name"], parameter["in"])
            if key in seen:
                raise ImporterError("OpenAPI parameter declaration cannot be represented safely")
            seen.add(key)
            merged[key] = parameter
    return list(merged.values())


def _swagger_scheme(raw_obj: dict[str, Any], operation: dict[str, Any] | None = None) -> bool:
    """Validate the effective Swagger 2 scheme and report alternatives."""
    owner = operation if operation is not None and "schemes" in operation else raw_obj
    schemes = owner.get("schemes")
    if schemes is None:
        selected_scheme = "https"
        has_alternatives = False
    else:
        if not isinstance(schemes, list) or not schemes or not all(isinstance(value, str) for value in schemes):
            raise ImporterError("Swagger scheme declaration is malformed")
        selected_scheme = schemes[0].lower()
        has_alternatives = len(schemes) > 1
    if selected_scheme != "https":
        raise ImporterError("Swagger transport cannot be represented safely")
    return has_alternatives


def _swagger_host_and_base(raw_obj: dict[str, Any]) -> tuple[str, str]:
    """Resolve a Swagger 2 authority and base path."""
    raw_host = raw_obj.get("host", "api.target.local")
    if not isinstance(raw_host, str) or not raw_host or _has_unsafe_location_character(raw_host):
        raise ImporterError("Swagger host is malformed")
    try:
        parsed_host = urlparse(f"//{raw_host}")
        parsed_hostname = parsed_host.hostname
        _ = parsed_host.port
    except ValueError:
        raise ImporterError("Swagger host cannot be represented safely") from None
    if (
        not parsed_host.netloc
        or not parsed_hostname
        or parsed_host.path
        or parsed_host.query
        or parsed_host.fragment
        or parsed_host.username is not None
        or parsed_host.password is not None
    ):
        raise ImporterError("Swagger host cannot be represented safely")
    host = _import_authority(f"//{raw_host}")

    base_path = raw_obj.get("basePath", "/")
    if (
        not isinstance(base_path, str)
        or not base_path.startswith("/")
        or "?" in base_path
        or "#" in base_path
        or _has_unsafe_location_character(base_path)
    ):
        raise ImporterError("Swagger base path is malformed")
    return host, base_path or "/"


def _security_definitions(raw_obj: dict[str, Any], is_swagger: bool) -> dict[str, Any]:
    if is_swagger:
        definitions = raw_obj.get("securityDefinitions", {})
    else:
        components = raw_obj.get("components", {})
        definitions = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    return definitions if isinstance(definitions, dict) else {}


def _resolve_security_scheme(definition: Any, is_swagger: bool) -> AuthenticationMechanism:
    """Resolve one referenced scheme without trusting its declaration name."""
    if not isinstance(definition, dict) or not isinstance(definition.get("type"), str):
        raise ImporterError("Referenced security scheme is malformed")
    scheme_type = definition["type"].lower()

    if (is_swagger and scheme_type == "basic") or (not is_swagger and scheme_type == "http"):
        raw_http_scheme = "basic" if is_swagger else definition.get("scheme")
        if not isinstance(raw_http_scheme, str):
            raise ImporterError("Referenced security scheme is malformed")
        http_scheme = raw_http_scheme.lower()
        if http_scheme not in ("basic", "bearer"):
            raise ImporterError("Referenced security scheme cannot be represented safely")
        return AuthenticationMechanism(
            auth_type=AuthType.BASIC.value if http_scheme == "basic" else AuthType.BEARER.value,
            token_name="Authorization",  # noqa: S106 -- HTTP header name, not a token value.
            location="header",
        )

    if scheme_type == "apikey":
        location = definition.get("in")
        name = definition.get("name")
        if location not in ("header", "query") or not isinstance(name, str) or not name:
            raise ImporterError("Referenced security scheme cannot be represented safely")
        if location == "header" and not _is_safe_auth_header_name(name):
            raise ImporterError("Referenced security scheme cannot be represented safely")
        return AuthenticationMechanism(auth_type=AuthType.API_KEY.value, token_name=name, location=location)

    if scheme_type == "oauth2":
        if is_swagger:
            flow = definition.get("flow")
            required_urls = {
                "implicit": ("authorizationUrl",),
                "password": ("tokenUrl",),
                "application": ("tokenUrl",),
                "accessCode": ("authorizationUrl", "tokenUrl"),
            }
            if flow not in required_urls or not isinstance(definition.get("scopes"), dict):
                raise ImporterError("Referenced security scheme is malformed")
            if any(
                not isinstance(definition.get(field), str) or not definition[field] for field in required_urls[flow]
            ):
                raise ImporterError("Referenced security scheme is malformed")
        else:
            flows = definition.get("flows")
            required_urls = {
                "implicit": ("authorizationUrl",),
                "password": ("tokenUrl",),
                "clientCredentials": ("tokenUrl",),
                "authorizationCode": ("authorizationUrl", "tokenUrl"),
            }
            if not isinstance(flows, dict) or not flows:
                raise ImporterError("Referenced security scheme is malformed")
            for flow_name, flow in flows.items():
                if (
                    flow_name not in required_urls
                    or not isinstance(flow, dict)
                    or not isinstance(flow.get("scopes"), dict)
                ):
                    raise ImporterError("Referenced security scheme is malformed")
                if any(not isinstance(flow.get(field), str) or not flow[field] for field in required_urls[flow_name]):
                    raise ImporterError("Referenced security scheme is malformed")
        return AuthenticationMechanism(
            auth_type=AuthType.OAUTH2.value,
            token_name="Authorization",  # noqa: S106 -- HTTP header name, not a token value.
            location="header",
        )

    raise ImporterError("Referenced security scheme cannot be represented safely")


def _declared_oauth_scopes(definition: dict[str, Any], is_swagger: bool) -> set[str]:
    """Return validated OAuth scope names from a referenced scheme."""
    scope_maps = [definition["scopes"]] if is_swagger else [flow["scopes"] for flow in definition["flows"].values()]
    if any(
        not all(isinstance(name, str) and name and isinstance(description, str) for name, description in scopes.items())
        for scopes in scope_maps
    ):
        raise ImporterError("Referenced security scheme is malformed")
    return {name for scopes in scope_maps for name in scopes}


def _validate_security_scopes(
    definition: dict[str, Any],
    mechanism: AuthenticationMechanism,
    scopes: list[str],
    is_swagger: bool,
) -> None:
    """Reject scope requirements the replay inventory cannot preserve."""
    if mechanism.auth_type != AuthType.OAUTH2.value:
        if scopes:
            raise ImporterError("OpenAPI security requirement cannot be represented safely")
        return

    declared_scopes = _declared_oauth_scopes(definition, is_swagger)
    if any(scope not in declared_scopes for scope in scopes):
        raise ImporterError("OpenAPI security requirement is malformed")
    if scopes:
        raise ImporterError("OpenAPI security requirement cannot be represented safely")


def _credential_destination(mechanism: AuthenticationMechanism) -> tuple[str, str]:
    """Return credential destination identity using HTTP name semantics."""
    name = mechanism.token_name.lower() if mechanism.location == "header" else mechanism.token_name
    return mechanism.location, name


def _authentication_signature(
    mechanisms: list[AuthenticationMechanism],
) -> tuple[tuple[str, str, str, str], ...]:
    """Return the redacted authentication-context identity for one request."""
    return tuple(
        sorted(
            (
                mechanism.auth_type,
                mechanism.location,
                mechanism.token_name.lower() if mechanism.location == "header" else mechanism.token_name,
                mechanism.credential_hash,
            )
            for mechanism in mechanisms
            if mechanism.auth_type != AuthType.NONE.value
        )
    )


def _bind_imported_sessions(
    endpoints: list[HttpEndpoint], provenance: EvidenceProvenance, role_id: str
) -> list[SessionContext]:
    """Create source-scoped sessions and explicitly bind singular authentication."""
    sessions: dict[tuple[str, str, str, str], SessionContext] = {}
    for endpoint in endpoints:
        active = [item for item in endpoint.auth_mechanisms if item.auth_type != AuthType.NONE.value]
        for mechanism in active:
            identity = _authentication_signature([mechanism])[0]
            session = sessions.get(identity)
            if session is None:
                canonical = json.dumps(
                    {"source_sha256": provenance.sha256, "authentication": identity},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                session = SessionContext(
                    session_id="sess-" + hashlib.sha256(canonical).hexdigest()[:20],
                    role_id=role_id,
                    auth_mechanism=mechanism,
                )
                sessions[identity] = session
        if len(active) == 1:
            endpoint.session_id = sessions[_authentication_signature(active)[0]].session_id
    return [sessions[key] for key in sorted(sessions)]


def _postman_auth_mechanism(raw_auth: Any) -> AuthenticationMechanism | None:
    """Normalize one supported Postman auth declaration without retaining credentials."""
    if not isinstance(raw_auth, dict):
        return None
    raw_type = raw_auth.get("type")
    if not isinstance(raw_type, str):
        raise ImporterError("Postman authentication declaration is malformed")
    auth_type = raw_type.lower()
    if auth_type == "noauth":
        return None
    values = raw_auth.get(raw_type, raw_auth.get(auth_type, []))
    if not isinstance(values, list):
        raise ImporterError("Postman authentication declaration is malformed")
    fields = {
        str(item.get("key", "")): str(item.get("value", ""))
        for item in values
        if isinstance(item, dict) and item.get("key")
    }
    credential_hash = hashlib.sha256(
        json.dumps(raw_auth, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    if auth_type in ("bearer", "basic"):
        return AuthenticationMechanism(
            auth_type=auth_type,
            token_name=_AUTHORIZATION_HEADER,
            location="header",
            is_redacted=True,
            credential_hash=credential_hash,
        )
    if auth_type in ("apikey", "api_key"):
        name = fields.get("key", "")
        location = fields.get("in", "header").lower()
        if (
            not name
            or location not in ("header", "query")
            or (location == "header" and not _is_safe_auth_header_name(name))
        ):
            raise ImporterError("Postman authentication declaration cannot be represented safely")
        return AuthenticationMechanism(
            auth_type=AuthType.API_KEY.value,
            token_name=name,
            location=location,
            is_redacted=True,
            credential_hash=credential_hash,
        )
    raise ImporterError("Postman authentication declaration cannot be represented safely")


def _operation_authentication(
    raw_obj: dict[str, Any],
    operation: dict[str, Any],
    definitions: dict[str, Any],
    is_swagger: bool,
) -> tuple[list[AuthenticationMechanism], bool]:
    """Validate effective security and resolve its selected alternative."""
    security = operation["security"] if "security" in operation else raw_obj.get("security", [])
    if not isinstance(security, list):
        raise ImporterError("OpenAPI security requirement is malformed")
    if not security:
        return [], False
    if not all(isinstance(requirement, dict) for requirement in security):
        raise ImporterError("OpenAPI security requirement is malformed")

    resolved_alternatives: list[list[AuthenticationMechanism]] = []
    for requirement in security:
        mechanisms: list[AuthenticationMechanism] = []
        occupied: set[tuple[str, str]] = set()
        for scheme_name, scopes in requirement.items():
            if (
                not isinstance(scheme_name, str)
                or not scheme_name
                or not isinstance(scopes, list)
                or not all(isinstance(scope, str) for scope in scopes)
            ):
                raise ImporterError("OpenAPI security requirement is malformed")
            if scheme_name not in definitions:
                raise ImporterError("OpenAPI operation references an unknown security scheme")
            definition = definitions[scheme_name]
            mechanism = _resolve_security_scheme(definition, is_swagger)
            _validate_security_scopes(definition, mechanism, scopes, is_swagger)
            destination = _credential_destination(mechanism)
            if destination in occupied:
                raise ImporterError("Operation security combination cannot be represented safely")
            occupied.add(destination)
            mechanisms.append(mechanism)
        resolved_alternatives.append(mechanisms)

    has_alternatives = len(resolved_alternatives) > 1
    if any(not mechanisms for mechanisms in resolved_alternatives):
        return [], has_alternatives
    return resolved_alternatives[0], has_alternatives


def import_har(
    har_data: dict[str, Any] | str | Path,
    source_id: str | None = None,
    provenance: EvidenceProvenance | None = None,
) -> ApiInventory:
    """Import and normalize HTTP traffic from HAR (HTTP Archive) format."""
    raw_obj, content = _load_json_data(har_data)
    provenance = _provenance(content, "har_import", source_id, provenance)

    log = raw_obj.get("log")
    if not isinstance(log, dict) or "entries" not in log:
        raise ImporterError("Invalid HAR document: missing 'log.entries'")

    endpoints_map: dict[tuple[str, str, str, str, tuple[tuple[str, str, str, str], ...]], HttpEndpoint] = {}
    target_hosts: set[str] = set()
    unsupported: list[UnsupportedFeature] = []

    for entry in log.get("entries", []):
        req = entry.get("request", {})
        res = entry.get("response", {})
        raw_url = req.get("url", "")
        if not raw_url:
            continue

        parsed_url = urlparse(raw_url)
        host = _import_authority(raw_url) or "unknown-host"
        target_hosts.add(host)
        path = parsed_url.path or "/"
        method = (req.get("method") or "GET").upper()

        headers_raw = req.get("headers", [])
        clean_headers, auth_mechs = _sanitize_headers(headers_raw)

        query_raw = req.get("queryString") or {
            k: v[0] for k, v in parse_qs(parsed_url.query, keep_blank_values=True).items()
        }
        clean_query, q_auth_mechs = _sanitize_query(query_raw)
        auth_mechs.extend(q_auth_mechs)
        auth_signature = _authentication_signature(auth_mechs)

        # Detect protocol & unsupported features
        proto = ApiProtocol.HTTP.value
        graphql_ops: list[str] = []
        websocket_subprotocols: list[str] = []

        if path.endswith("/graphql") or "graphql" in path.lower():
            proto = ApiProtocol.GRAPHQL.value
            graphql_ops.append("query")
        elif clean_headers.get("Upgrade", "").lower() == "websocket" or parsed_url.scheme in ("ws", "wss"):
            proto = ApiProtocol.WEBSOCKET.value
            if "_webSocketMessages" in entry:
                unsupported.append(
                    UnsupportedFeature(
                        protocol=proto,
                        feature_name="binary_websocket_frames",
                        reason="Binary streaming WebSocket frames cannot be automatically replayed",
                        affected_endpoints=[f"{method} {path}"],
                    )
                )

        status_code = res.get("status")
        resp_codes = [status_code] if status_code else []

        body_schema = {}
        post_data = req.get("postData")
        if isinstance(post_data, dict):
            mime_type = post_data.get("mimeType", "application/json")
            text = post_data.get("text", "")
            body_schema = {"mimeType": mime_type, "sample_length": len(text)}

        key = (parsed_url.scheme.lower(), host, method, path, auth_signature)
        if key not in endpoints_map:
            endpoint_id = (
                "ep-" + hashlib.sha256(f"{parsed_url.scheme.lower()}:{host}:{method}:{path}".encode()).hexdigest()[:12]
            )
            endpoints_map[key] = HttpEndpoint(
                endpoint_id=endpoint_id,
                method=method,
                path=path,
                host=host,
                scheme=parsed_url.scheme.lower(),
                protocol=proto,
                summary=f"{method} {path}",
                query_parameters=clean_query,
                headers_schema=clean_headers,
                request_body_schema=body_schema,
                response_status_codes=resp_codes,
                auth_mechanisms=auth_mechs,
                roles_allowed=["anonymous" if not auth_mechs else "authenticated"],
                graphql_operations=graphql_ops,
                websocket_subprotocols=websocket_subprotocols,
            )
        else:
            ep = endpoints_map[key]
            ep.query_parameters.update(clean_query)
            ep.headers_schema.update(clean_headers)
            if status_code and status_code not in ep.response_status_codes:
                ep.response_status_codes.append(status_code)
            for am in auth_mechs:
                if am.token_name not in [x.token_name for x in ep.auth_mechanisms]:
                    ep.auth_mechanisms.append(am)

    route_counts: dict[tuple[str, str, str, str], int] = {}
    for key in endpoints_map:
        route = key[:4]
        route_counts[route] = route_counts.get(route, 0) + 1
    for key, endpoint in endpoints_map.items():
        route = key[:4]
        if route_counts[route] > 1:
            variant_identity = json.dumps(
                {"route": route, "authentication": key[4]},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            endpoint.endpoint_id = "ep-" + hashlib.sha256(variant_identity).hexdigest()[:12]

    endpoints = list(endpoints_map.values())
    sessions = _bind_imported_sessions(endpoints, provenance, "role-auth")
    inv_id = f"inv-{hashlib.sha256(f'har:{provenance.sha256}'.encode()).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name="HAR Imported API Inventory",
        target_hosts=sorted(target_hosts),
        endpoints=endpoints,
        roles=[
            UserRole(role_id="role-anon", role_name="anonymous", permissions=["read_public"]),
            UserRole(role_id="role-auth", role_name="authenticated", permissions=["read_api", "execute_request"]),
        ],
        sessions=sessions,
        unsupported_features=unsupported,
        imported_sources=["HAR 1.2 traffic capture"],
        credentials_redacted=True,
        provenance=provenance,
    )


def import_openapi(
    openapi_data: dict[str, Any] | str | Path,
    source_id: str | None = None,
    provenance: EvidenceProvenance | None = None,
) -> ApiInventory:
    """Import and normalize API inventory from OpenAPI 3.x or Swagger 2.0 specification."""
    raw_obj, content = _load_json_data(openapi_data)
    provenance = _provenance(content, "openapi_import", source_id, provenance)

    openapi_version = raw_obj.get("openapi")
    is_swagger = raw_obj.get("swagger") == "2.0" and "openapi" not in raw_obj
    is_openapi = (
        isinstance(openapi_version, str)
        and re.fullmatch(r"3\.[0-9]+\.[0-9]+", openapi_version) is not None
        and "swagger" not in raw_obj
    )
    if not (is_swagger or is_openapi):
        raise ImporterError("Invalid OpenAPI document: unsupported or conflicting version")

    if "paths" not in raw_obj or not isinstance(raw_obj["paths"], dict):
        raise ImporterError("Invalid OpenAPI document: missing 'paths' mapping")

    info = raw_obj.get("info", {})
    title = info.get("title", "OpenAPI Service") if isinstance(info, dict) else "OpenAPI Service"
    title = safe_inventory_public_label(str(title), "OpenAPI Service")
    definitions = _security_definitions(raw_obj, is_swagger)
    target_hosts: set[str] = set()

    endpoints: list[HttpEndpoint] = []
    unsupported: list[UnsupportedFeature] = []

    swagger_location: tuple[str, str] | None = None
    if is_swagger:
        swagger_location = _swagger_host_and_base(raw_obj)
        target_hosts.add(swagger_location[0])

    for path, path_item in raw_obj["paths"].items():
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "?" in path
            or "#" in path
            or _has_unsafe_location_character(path)
        ):
            raise ImporterError("OpenAPI operation path cannot be represented safely")
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method not in path_item:
                continue

            op = path_item[method]
            if not isinstance(op, dict):
                continue

            if swagger_location is not None:
                host, prefix = swagger_location
                has_server_alternatives = _swagger_scheme(raw_obj, op)
            else:
                host, prefix, has_server_alternatives = _selected_openapi_server(raw_obj, path_item, op)
            effective_path = _join_api_paths(prefix, path)
            target_hosts.add(host)
            if has_server_alternatives:
                unsupported.append(
                    UnsupportedFeature(
                        protocol=ApiProtocol.HTTP.value,
                        feature_name="server_alternatives",
                        reason="Only the first applicable declared server can be represented by one endpoint",
                        affected_endpoints=[f"{method.upper()} {effective_path}"],
                    )
                )

            summary = op.get("summary", f"{method.upper()} {path}")
            tags_value = op.get("tags", [])
            tags = list(tags_value) if isinstance(tags_value, list) else []
            deprecated = bool(op.get("deprecated", False))

            query_params: dict[str, str] = {}
            header_params: dict[str, str] = {}
            for param in _openapi_parameters(path_item, op):
                p_in = param["in"]
                p_name = param["name"]
                if p_in == "query":
                    query_params[p_name] = (
                        redact_credential_value("sample_val") if SENSITIVE_FIELD_PATTERNS.search(p_name) else "string"
                    )
                elif p_in == "header":
                    header_params[p_name] = (
                        redact_credential_value("sample_val") if SENSITIVE_FIELD_PATTERNS.search(p_name) else "string"
                    )

            # Response status codes
            responses = op.get("responses", {})
            status_codes: list[int] = []
            if isinstance(responses, dict):
                for code_key in responses:
                    try:
                        status_codes.append(int(code_key))
                    except (TypeError, ValueError):
                        pass

            # Body schema
            body_schema = {}
            if "requestBody" in op and isinstance(op["requestBody"], dict):
                body_content = op["requestBody"].get("content", {})
                if isinstance(body_content, dict):
                    for ctype, cval in body_content.items():
                        if isinstance(cval, dict):
                            body_schema[ctype] = cval.get("schema", {})

            proto = ApiProtocol.HTTP.value
            graphql_ops: list[str] = []
            if "graphql" in effective_path.lower():
                proto = ApiProtocol.GRAPHQL.value
                graphql_ops.append("query")
            elif "websocket" in effective_path.lower() or effective_path.endswith("/ws"):
                proto = ApiProtocol.WEBSOCKET.value

            op_auth, has_security_alternatives = _operation_authentication(raw_obj, op, definitions, is_swagger)
            if has_security_alternatives:
                unsupported.append(
                    UnsupportedFeature(
                        protocol=proto,
                        feature_name="security_alternatives",
                        reason="Only one declared security alternative can be represented by one endpoint",
                        affected_endpoints=[f"{method.upper()} {effective_path}"],
                    )
                )
            endpoint_id = f"ep-{hashlib.sha256(f'{host}:{method.upper()}:{effective_path}'.encode()).hexdigest()[:12]}"
            endpoints.append(
                HttpEndpoint(
                    endpoint_id=endpoint_id,
                    method=method.upper(),
                    path=effective_path,
                    host=host,
                    protocol=proto,
                    summary=summary,
                    query_parameters=query_params,
                    headers_schema=header_params,
                    request_body_schema=body_schema,
                    response_status_codes=status_codes,
                    auth_mechanisms=op_auth,
                    roles_allowed=["authenticated" if op_auth else "anonymous"],
                    tags=tags,
                    deprecated=deprecated,
                    graphql_operations=graphql_ops,
                )
            )

    if is_swagger and not endpoints:
        _swagger_scheme(raw_obj)
    if not target_hosts:
        target_hosts.add("api.target.local")

    sessions = _bind_imported_sessions(endpoints, provenance, "role-auth")
    inv_id = f"inv-{hashlib.sha256(f'openapi:{provenance.sha256}'.encode()).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name=f"OpenAPI Spec: {title}",
        target_hosts=sorted(target_hosts),
        endpoints=endpoints,
        roles=[
            UserRole(role_id="role-anon", role_name="anonymous", permissions=["read_public"]),
            UserRole(role_id="role-auth", role_name="authenticated", permissions=["api_read", "execute_request"]),
        ],
        sessions=sessions,
        unsupported_features=unsupported,
        imported_sources=[f"OpenAPI 3.x / Swagger: {title}"],
        credentials_redacted=True,
        provenance=provenance,
    )


def import_postman(
    postman_data: dict[str, Any] | str | Path,
    source_id: str | None = None,
    provenance: EvidenceProvenance | None = None,
) -> ApiInventory:
    """Import and normalize Postman Collection (v2.0 / v2.1) into ApiInventory."""
    raw_obj, content = _load_json_data(postman_data)
    provenance = _provenance(content, "postman_import", source_id, provenance)

    info = raw_obj.get("info", {})
    title = safe_inventory_public_label(str(info.get("name", "Postman Collection")), "Postman Collection")
    items = raw_obj.get("item", [])
    if not isinstance(items, list):
        raise ImporterError("Invalid Postman Collection: missing 'item' array")

    endpoints: list[HttpEndpoint] = []
    target_hosts: set[str] = set()

    def _traverse(item_list: list[dict[str, Any]], inherited_auth: Any = None) -> None:
        for it in item_list:
            if not isinstance(it, dict):
                continue
            item_auth = it.get("auth", inherited_auth)
            if "item" in it and isinstance(it["item"], list):
                _traverse(it["item"], item_auth)
                continue

            req = it.get("request")
            if not isinstance(req, dict):
                continue

            method = req.get("method", "GET").upper()
            url_obj = req.get("url", "")
            raw_url = url_obj if isinstance(url_obj, str) else url_obj.get("raw", "")
            if isinstance(url_obj, dict) and not raw_url:
                hostname = url_obj.get("host", "")
                hostname = ".".join(hostname) if isinstance(hostname, list) else hostname
                port = f":{url_obj['port']}" if url_obj.get("port") else ""
                segments = url_obj.get("path", "")
                path_value = "/".join(segments) if isinstance(segments, list) else segments
                raw_url = f"{url_obj.get('protocol', 'https')}://{hostname}{port}/{path_value.lstrip('/')}"
            parsed = urlparse(raw_url)
            host = _import_authority(raw_url) or "postman.target.local"
            target_hosts.add(host)
            path = parsed.path or "/"

            headers_raw = req.get("header", [])
            clean_headers, auth_mechs = _sanitize_headers(headers_raw)

            # Query params
            query_raw = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
            if isinstance(url_obj, dict) and "query" in url_obj:
                query_raw = url_obj["query"]
            clean_query, q_auths = _sanitize_query(query_raw)
            auth_mechs.extend(q_auths)

            declared_auth = _postman_auth_mechanism(req.get("auth", item_auth))
            if declared_auth is not None:
                occupied = {_credential_destination(mechanism) for mechanism in auth_mechs}
                if _credential_destination(declared_auth) not in occupied:
                    auth_mechs.append(declared_auth)

            endpoint_identity = f"{provenance.sha256}:{len(endpoints)}:{host}:{method}:{path}"
            endpoint_id = f"ep-{hashlib.sha256(endpoint_identity.encode()).hexdigest()[:12]}"
            endpoints.append(
                HttpEndpoint(
                    endpoint_id=endpoint_id,
                    method=method,
                    path=path,
                    host=host,
                    scheme=parsed.scheme.lower(),
                    protocol=ApiProtocol.WEBSOCKET.value if parsed.scheme in ("ws", "wss") else ApiProtocol.HTTP.value,
                    summary=safe_inventory_public_label(it.get("name", f"{method} {path}"), f"{method} endpoint"),
                    query_parameters=clean_query,
                    headers_schema=clean_headers,
                    auth_mechanisms=auth_mechs or [AuthenticationMechanism(auth_type=AuthType.NONE.value)],
                    roles_allowed=["postman_user"],
                )
            )

    _traverse(items, raw_obj.get("auth"))

    sessions = _bind_imported_sessions(endpoints, provenance, "role-postman")
    inv_id = f"inv-{hashlib.sha256(f'postman:{provenance.sha256}'.encode()).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name=f"Postman: {title}",
        target_hosts=sorted(target_hosts),
        endpoints=endpoints,
        roles=[UserRole(role_id="role-postman", role_name="postman_user", permissions=["replay"])],
        sessions=sessions,
        imported_sources=[f"Postman Collection: {title}"],
        credentials_redacted=True,
        provenance=provenance,
    )


def import_raw_http(
    raw_text: str | Path,
    host: str = "raw.target.local",
    source_id: str | None = None,
    provenance: EvidenceProvenance | None = None,
) -> ApiInventory:
    """Parse raw HTTP request text into an ApiInventory containing a modeled endpoint."""
    content = _input_bytes(raw_text)
    try:
        text_content = content.decode("utf-8")
    except UnicodeError:
        raise ImporterError("Invalid raw HTTP encoding") from None
    provenance = _provenance(content, "raw_http_import", source_id, provenance)

    lines = text_content.strip().splitlines()
    if not lines:
        raise ImporterError("Empty raw HTTP input")

    req_line = lines[0].strip().split()
    if len(req_line) != 3 or not req_line[2].startswith("HTTP/"):
        raise ImporterError("Malformed HTTP request line")

    method = req_line[0].upper()
    uri = req_line[1]
    parsed = urlparse(uri)
    path = parsed.path or "/"

    headers_raw: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False

    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
        elif not line.strip():
            in_body = True
        else:
            parts = line.split(":", 1)
            if len(parts) == 2:
                name = parts[0].strip()
                if name.lower() == "host" and any(key.lower() == "host" for key in headers_raw):
                    raise ImporterError("Ambiguous raw HTTP Host headers")
                headers_raw[name] = parts[1].strip()

    host_values = [value for name, value in headers_raw.items() if name.lower() == "host"]
    if len(host_values) > 1:
        raise ImporterError("Ambiguous raw HTTP Host headers")
    host = _import_authority("//" + (host_values[0] if host_values else host))
    if parsed.netloc:
        absolute_host = _import_authority(uri)
        if host_values and absolute_host != host:
            raise ImporterError("Conflicting raw HTTP authorities")
        host = absolute_host

    clean_headers, auth_mechs = _sanitize_headers(headers_raw)

    clean_query = {}
    if parsed.query:
        q_dict = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        clean_query, q_auths = _sanitize_query(q_dict)
        auth_mechs.extend(q_auths)

    body_text = "\n".join(body_lines).strip()
    body_schema = {"sample_length": len(body_text)} if body_text else {}

    endpoint_id = f"ep-{hashlib.sha256(f'{host}:{method}:{path}'.encode()).hexdigest()[:12]}"
    endpoint = HttpEndpoint(
        endpoint_id=endpoint_id,
        method=method,
        path=path,
        host=host,
        scheme=parsed.scheme.lower(),
        summary=f"Raw HTTP {method} {path}",
        query_parameters=clean_query,
        headers_schema=clean_headers,
        request_body_schema=body_schema,
        auth_mechanisms=auth_mechs or [AuthenticationMechanism(auth_type=AuthType.NONE.value)],
        roles_allowed=["anonymous" if not auth_mechs else "authenticated"],
    )

    sessions = _bind_imported_sessions([endpoint], provenance, "role-raw")
    inv_id = f"inv-{hashlib.sha256(f'raw:{provenance.sha256}'.encode()).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name=f"Raw HTTP: {method} {path}",
        target_hosts=[host],
        endpoints=[endpoint],
        roles=[UserRole(role_id="role-raw", role_name="operator", permissions=["replay"])],
        sessions=sessions,
        imported_sources=["Raw HTTP Request"],
        credentials_redacted=True,
        provenance=provenance,
    )
