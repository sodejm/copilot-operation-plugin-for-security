"""Importers and parsers for HTTP traffic, OpenAPI, Postman, and raw HTTP descriptions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from cops.evidence.canonical import utc_now
from cops.discovery.models import EvidenceProvenance
from .models import (
    ApiInventory,
    ApiProtocol,
    AuthenticationMechanism,
    AuthType,
    HttpEndpoint,
    SENSITIVE_FIELD_PATTERNS,
    SessionContext,
    UnsupportedFeature,
    UserRole,
    redact_credential_value,
)
from .sanitization import authority, sanitize_text


class ImporterError(Exception):
    """Raised when an import input format is malformed or invalid."""


def _sanitize_headers(headers: list[dict[str, Any]] | dict[str, Any]) -> tuple[dict[str, str], list[AuthenticationMechanism]]:
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
                    token_name=scheme.title() if scheme in ("bearer", "basic") else "Authorization",
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


def _sanitize_query(query_dict: dict[str, str] | list[dict[str, str]]) -> tuple[dict[str, str], list[AuthenticationMechanism]]:
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


def _input_bytes(data: dict[str, Any] | str | Path) -> bytes:
    """Read once, retaining exact UTF-8 bytes for content provenance."""
    try:
        if isinstance(data, dict):
            return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if isinstance(data, Path):
            return data.read_bytes()
        if isinstance(data, str):
            # JSON and HTTP payloads must never be probed as filesystem paths.
            if len(data) < 240 and not any(char in data for char in '\r\n{["'):
                candidate = Path(data)
                if candidate.is_file():
                    return candidate.read_bytes()
            return data.encode("utf-8")
    except (OSError, ValueError, TypeError, RecursionError):
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
    if supplied is not None and supplied.sha256 != content_hash:
        raise ImporterError("API import provenance does not match input content")
    return EvidenceProvenance(
        source_id=source_id or (supplied.source_id if supplied else f"source-{content_hash[:12]}"),
        source_type=kind,
        sha256=content_hash,
        timestamp=supplied.timestamp if supplied else utc_now(),
        path_or_uri=f"sha256:{content_hash}",
    )


def _import_authority(url: str) -> str:
    try:
        return authority(url)
    except ValueError:
        raise ImporterError("Invalid API import authority") from None


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

    endpoints_map: dict[tuple[str, str, str, str], HttpEndpoint] = {}
    target_hosts: set[str] = set()
    unsupported: list[UnsupportedFeature] = []

    for idx, entry in enumerate(log.get("entries", [])):
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

        key = (parsed_url.scheme.lower(), host, method, path)
        if key not in endpoints_map:
            endpoint_id = (
                f"ep-{hashlib.sha256(f'{parsed_url.scheme.lower()}:{host}:{method}:{path}'.encode()).hexdigest()[:12]}"
            )
            endpoints_map[key] = HttpEndpoint(
                endpoint_id=endpoint_id,
                method=method,
                path=path,
                host=host,
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

    inv_id = f"inv-{hashlib.sha256(f'har:{len(endpoints_map)}:{sorted(target_hosts)}'.encode('utf-8')).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name="HAR Imported API Inventory",
        target_hosts=sorted(target_hosts),
        endpoints=list(endpoints_map.values()),
        roles=[
            UserRole(role_id="role-anon", role_name="anonymous", permissions=["read_public"]),
            UserRole(role_id="role-auth", role_name="authenticated", permissions=["read_api", "execute_request"]),
        ],
        sessions=[
            SessionContext(
                session_id="sess-imported-01",
                role_id="role-auth",
                auth_mechanism=AuthenticationMechanism(auth_type=AuthType.BEARER.value, token_name="Authorization"),
            )
        ],
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

    if "paths" not in raw_obj or not isinstance(raw_obj["paths"], dict):
        raise ImporterError("Invalid OpenAPI document: missing 'paths' mapping")

    title = raw_obj.get("info", {}).get("title", "OpenAPI Service")
    target_hosts: set[str] = set()

    # Extract hosts from servers (OpenAPI 3) or host (Swagger 2)
    if "servers" in raw_obj and isinstance(raw_obj["servers"], list):
        for s in raw_obj["servers"]:
            u = s.get("url", "")
            if u:
                p = urlparse(u)
                if p.netloc:
                    target_hosts.add(_import_authority(u))
    elif "host" in raw_obj:
        target_hosts.add(_import_authority("//" + str(raw_obj["host"])))

    if not target_hosts:
        target_hosts.add("api.target.local")

    default_host = sorted(target_hosts)[0]

    # Parse security schemes
    sec_schemes = raw_obj.get("components", {}).get("securitySchemes", {}) or raw_obj.get("securityDefinitions", {})
    global_auth_mechs: list[AuthenticationMechanism] = []
    for s_name, s_def in sec_schemes.items():
        stype = s_def.get("type", "").lower()
        if stype in ("http",):
            scheme = s_def.get("scheme", "").lower()
            atype = AuthType.BEARER.value if scheme == "bearer" else AuthType.BASIC.value
            global_auth_mechs.append(AuthenticationMechanism(auth_type=atype, token_name=s_name, location="header"))
        elif stype in ("apikey",):
            in_loc = s_def.get("in", "header")
            param_name = s_def.get("name", s_name)
            global_auth_mechs.append(AuthenticationMechanism(auth_type=AuthType.API_KEY.value, token_name=param_name, location=in_loc))
        elif stype in ("oauth2",):
            global_auth_mechs.append(AuthenticationMechanism(auth_type=AuthType.OAUTH2.value, token_name="Authorization", location="header"))

    endpoints: list[HttpEndpoint] = []
    unsupported: list[UnsupportedFeature] = []

    for path, path_item in raw_obj["paths"].items():
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method not in path_item:
                continue

            op = path_item[method]
            if not isinstance(op, dict):
                continue

            summary = op.get("summary", f"{method.upper()} {path}")
            tags = list(op.get("tags", []))
            deprecated = bool(op.get("deprecated", False))

            query_params: dict[str, str] = {}
            header_params: dict[str, str] = {}
            for param in op.get("parameters", []):
                p_in = param.get("in")
                p_name = param.get("name", "")
                if p_in == "query":
                    query_params[p_name] = redact_credential_value("sample_val") if SENSITIVE_FIELD_PATTERNS.search(p_name) else "string"
                elif p_in == "header":
                    header_params[p_name] = redact_credential_value("sample_val") if SENSITIVE_FIELD_PATTERNS.search(p_name) else "string"

            # Response status codes
            responses = op.get("responses", {})
            status_codes: list[int] = []
            for code_key in responses.keys():
                try:
                    status_codes.append(int(code_key))
                except ValueError:
                    pass

            # Body schema
            body_schema = {}
            if "requestBody" in op and isinstance(op["requestBody"], dict):
                content = op["requestBody"].get("content", {})
                for ctype, cval in content.items():
                    body_schema[ctype] = cval.get("schema", {})

            proto = ApiProtocol.HTTP.value
            graphql_ops: list[str] = []
            if "graphql" in path.lower():
                proto = ApiProtocol.GRAPHQL.value
                graphql_ops.append("query")
            elif "websocket" in path.lower() or path.endswith("/ws"):
                proto = ApiProtocol.WEBSOCKET.value

            # Endpoint auth
            op_auth = list(global_auth_mechs) if ("security" in op or global_auth_mechs) else []
            for param in op.get("parameters", []):
                p_in = param.get("in", "")
                p_name = param.get("name", "")
                if SENSITIVE_FIELD_PATTERNS.search(p_name):
                    op_auth.append(AuthenticationMechanism(auth_type=AuthType.API_KEY.value, token_name=p_name, location=p_in or "header"))
            if not op_auth:
                op_auth = [AuthenticationMechanism(auth_type=AuthType.NONE.value)]

            endpoint_id = f"ep-{hashlib.sha256(f'{default_host}:{method.upper()}:{path}'.encode('utf-8')).hexdigest()[:12]}"
            endpoints.append(
                HttpEndpoint(
                    endpoint_id=endpoint_id,
                    method=method.upper(),
                    path=path,
                    host=default_host,
                    protocol=proto,
                    summary=summary,
                    query_parameters=query_params,
                    headers_schema=header_params,
                    request_body_schema=body_schema,
                    response_status_codes=status_codes,
                    auth_mechanisms=op_auth,
                    roles_allowed=["admin" if "admin" in path else "user"],
                    tags=tags,
                    deprecated=deprecated,
                    graphql_operations=graphql_ops,
                )
            )

    inv_id = f"inv-{hashlib.sha256(f'openapi:{title}:{len(endpoints)}'.encode('utf-8')).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name=f"OpenAPI Spec: {title}",
        target_hosts=sorted(target_hosts),
        endpoints=endpoints,
        roles=[
            UserRole(role_id="role-user", role_name="user", permissions=["api_read"]),
            UserRole(role_id="role-admin", role_name="admin", permissions=["api_read", "api_write", "admin_config"]),
        ],
        sessions=[
            SessionContext(
                session_id="sess-openapi-01",
                role_id="role-user",
                auth_mechanism=global_auth_mechs[0] if global_auth_mechs else AuthenticationMechanism(),
            )
        ],
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
    title = info.get("name", "Postman Collection")
    items = raw_obj.get("item", [])
    if not isinstance(items, list):
        raise ImporterError("Invalid Postman Collection: missing 'item' array")

    endpoints: list[HttpEndpoint] = []
    target_hosts: set[str] = set()

    def _traverse(item_list: list[dict[str, Any]]) -> None:
        for it in item_list:
            if "item" in it and isinstance(it["item"], list):
                _traverse(it["item"])
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

            # Check postman auth field
            req_auth = req.get("auth")
            if isinstance(req_auth, dict):
                atype = req_auth.get("type", "").lower()
                auth_mechs.append(
                    AuthenticationMechanism(
                        auth_type=atype if atype in [a.value for a in AuthType] else AuthType.BEARER.value,
                        token_name=f"postman-{atype}" if atype in [a.value for a in AuthType] else "postman-custom",
                        location="header",
                        is_redacted=True,
                        credential_hash=hashlib.sha256(json.dumps(req_auth).encode("utf-8")).hexdigest(),
                    )
                )

            # Query params
            query_raw = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
            if isinstance(url_obj, dict) and "query" in url_obj:
                query_raw = url_obj["query"]
            clean_query, q_auths = _sanitize_query(query_raw)
            auth_mechs.extend(q_auths)

            endpoint_id = f"ep-{hashlib.sha256(f'{host}:{method}:{path}'.encode('utf-8')).hexdigest()[:12]}"
            endpoints.append(
                HttpEndpoint(
                    endpoint_id=endpoint_id,
                    method=method,
                    path=path,
                    host=host,
                    protocol=ApiProtocol.HTTP.value,
                    summary=it.get("name", f"{method} {path}"),
                    query_parameters=clean_query,
                    headers_schema=clean_headers,
                    auth_mechanisms=auth_mechs or [AuthenticationMechanism(auth_type=AuthType.NONE.value)],
                    roles_allowed=["postman_user"],
                )
            )

    _traverse(items)

    inv_id = f"inv-{hashlib.sha256(f'postman:{title}:{len(endpoints)}'.encode('utf-8')).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name=f"Postman: {title}",
        target_hosts=sorted(target_hosts),
        endpoints=endpoints,
        roles=[UserRole(role_id="role-postman", role_name="postman_user", permissions=["replay"])],
        sessions=[],
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

    for l in lines[1:]:
        if in_body:
            body_lines.append(l)
        elif not l.strip():
            in_body = True
        else:
            parts = l.split(":", 1)
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

    endpoint_id = f"ep-{hashlib.sha256(f'{host}:{method}:{path}'.encode('utf-8')).hexdigest()[:12]}"
    endpoint = HttpEndpoint(
        endpoint_id=endpoint_id,
        method=method,
        path=path,
        host=host,
        summary=f"Raw HTTP {method} {path}",
        query_parameters=clean_query,
        headers_schema=clean_headers,
        request_body_schema=body_schema,
        auth_mechanisms=auth_mechs or [AuthenticationMechanism(auth_type=AuthType.NONE.value)],
        roles_allowed=["anonymous" if not auth_mechs else "authenticated"],
    )

    inv_id = f"inv-{hashlib.sha256(f'raw:{host}:{method}:{path}'.encode('utf-8')).hexdigest()[:12]}"
    return ApiInventory(
        inventory_id=inv_id,
        name=f"Raw HTTP: {method} {path}",
        target_hosts=[host],
        endpoints=[endpoint],
        roles=[UserRole(role_id="role-raw", role_name="operator", permissions=["replay"])],
        sessions=[],
        imported_sources=["Raw HTTP Request"],
        credentials_redacted=True,
        provenance=provenance,
    )
