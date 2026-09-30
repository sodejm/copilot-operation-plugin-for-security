"""Redaction utilities to sanitize sensitive tokens and parameters in reports."""

from __future__ import annotations

import re
from typing import Any

PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(api[-_]?key\s*[:=]\s*)[A-Za-z0-9\-._~+/]+", re.IGNORECASE), r"\1[REDACTED_API_KEY]"),
    (re.compile(r"(password\s*[:=]\s*)[^\s,;]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(secret\s*[:=]\s*)[^\s,;]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}", re.IGNORECASE), "[REDACTED_OPENAI_KEY]"),
]


def redact_text(text: str) -> str:
    """Redact sensitive patterns from text."""
    if not isinstance(text, str):
        return str(text)
    sanitized = text
    for pattern, replacement in PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact dictionary keys and values."""
    sanitized: dict[str, Any] = {}
    sensitive_keys = {"token", "secret", "password", "api_key", "credential", "auth"}
    for k, v in data.items():
        if any(s in k.lower() for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, str):
            sanitized[k] = redact_text(v)
        elif isinstance(v, dict):
            sanitized[k] = redact_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [redact_text(item) if isinstance(item, str) else item for item in v]
        else:
            sanitized[k] = v
    return sanitized
