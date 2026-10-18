"""Lossy report sanitization; never use these values to construct wire requests."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_FIELD_PATTERNS = re.compile(
    r"(?i)(password|secret|token|auth|key|bearer|credential|session|cookie|private|jwt)"
)
_MARKER = re.compile(r"\[REDACTED:[0-9a-f]{12}\]")
_REFERENCES = re.compile(r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://|//)[^\s<>\"']+|[\w./~%+-]*\?[^\s<>\"']+")
_BEARER = re.compile(r"(?i)\bBearer\s+([^\s,;\"']+)")
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|secret|token|api_key|access_token|refresh_token|credential|auth|key|session|cookie|jwt)\b\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
)


def redact_credential_value(value: str) -> str:
    """Retain only exact redaction markers, never a marker with a payload suffix."""
    if not value or _MARKER.fullmatch(value):
        return value
    return f"[REDACTED:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}]"


def authority(url: str) -> str:
    """Canonical host and explicit port, with no URL user information."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{parsed.port}" if parsed.port is not None else host


def sanitize_reference(value: str) -> str:
    """Redact every query value and fragment in absolute or relative references."""
    try:
        parsed = urlsplit(value)
        query = urlencode(
            [(key, redact_credential_value(item)) for key, item in parse_qsl(parsed.query, keep_blank_values=True)],
            safe="[]:",
        )
        return urlunsplit(
            (
                parsed.scheme,
                authority(value) if parsed.netloc else "",
                parsed.path,
                query,
                redact_credential_value(parsed.fragment),
            )
        )
    except ValueError:
        return redact_credential_value(value)


def sanitize_text(value: str) -> str:
    """Remove recognizable credentials and URL values from free-form metadata."""
    value = _REFERENCES.sub(lambda match: sanitize_reference(match.group()), value)
    value = _BEARER.sub(lambda match: "Bearer " + redact_credential_value(match[1]), value)
    return _ASSIGNMENT.sub(lambda match: match[1] + redact_credential_value(match[2]), value)


def sanitize_tree(value: Any, *, sensitive_keys: bool = False, depth: int = 0) -> Any:
    """Copy JSON-compatible values, with explicit payload versus metadata policy."""
    if depth >= 32:
        return "[REDACTED:depth-limit]"
    if isinstance(value, dict):
        return {
            key: redact_credential_value(str(item))
            if sensitive_keys and SENSITIVE_FIELD_PATTERNS.search(key)
            else sanitize_tree(item, sensitive_keys=sensitive_keys, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_tree(item, sensitive_keys=sensitive_keys, depth=depth + 1) for item in value]
    return sanitize_text(value) if isinstance(value, str) else value


def redact_mapping(values: dict[str, str]) -> dict[str, str]:
    """Sanitize header values, including redirects carried in ordinary headers."""
    return {
        key: redact_credential_value(value) if SENSITIVE_FIELD_PATTERNS.search(key) else sanitize_text(value)
        for key, value in values.items()
    }


def sanitize_body(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        payload = json.loads(value)
    except (ValueError, RecursionError):
        return sanitize_text(value)
    return json.dumps(sanitize_tree(payload, sensitive_keys=True), sort_keys=True)
