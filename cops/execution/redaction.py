"""Stream redaction and credential masking for COPS execution runtime.

Guarantees that sensitive tokens, passwords, private keys, bearer headers,
and known engagement credentials are redacted from outputs and logs.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

# Common credential and token regex patterns
DEFAULT_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{16,})\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b")),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
    ("PASSWORD_PARAM", re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*([^\s;,\"'&]{4,})")),
]


class StreamRedactor:
    """Masks secrets and credentials in text and byte streams."""

    def __init__(
        self,
        known_secrets: Sequence[str] | None = None,
        custom_patterns: Sequence[tuple[str, re.Pattern[str]]] | None = None,
    ) -> None:
        self.known_secrets = [s for s in (known_secrets or []) if s and len(s) >= 4]
        # Sort secrets by length descending to match longest secret first
        self.known_secrets.sort(key=len, reverse=True)
        self.patterns = list(custom_patterns or DEFAULT_SENSITIVE_PATTERNS)

    def redact_string(self, text: str) -> str:
        """Alias for redact string."""
        return self.redact(text)

    def redact(self, text: str) -> str:
        """Redact sensitive patterns and known secrets from text string."""
        if not text:
            return text

        result = text

        # 1. Redact known exact secrets first
        for secret in self.known_secrets:
            if secret in result:
                result = result.replace(secret, "[REDACTED:SECRET]")

        # 2. Redact regex patterns
        for label, pattern in self.patterns:
            if label == "PRIVATE_KEY":
                result = pattern.sub("[REDACTED:PRIVATE_KEY]", result)
            elif label == "BEARER_TOKEN":
                result = pattern.sub("Bearer [REDACTED:TOKEN]", result)
            elif label == "PASSWORD_PARAM":
                result = pattern.sub(r"\1=[REDACTED:CREDENTIAL]", result)
            else:
                result = pattern.sub(f"[REDACTED:{label}]", result)

        return result

    def redact_bytes(self, data: bytes, encoding: str = "utf-8", errors: str = "replace") -> bytes:
        """Redact sensitive patterns from raw byte streams."""
        text = data.decode(encoding, errors=errors)
        redacted_text = self.redact(text)
        return redacted_text.encode(encoding, errors=errors)
