"""Decode bounded fixture JSON without requiring the COPS source runtime."""

from __future__ import annotations

import json


class JSONInputError(ValueError):
    """A fixed error code that does not include untrusted input."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def decode_json(raw: bytes, *, max_bytes: int = 65536, max_depth: int = 32):
    """Reject duplicate keys, nonfinite numbers, invalid Unicode and excess depth."""
    if type(max_bytes) is not int or max_bytes <= 0 or type(max_depth) is not int or not 1 <= max_depth <= 64:
        raise JSONInputError("invalid_limit")
    if type(raw) is not bytes or len(raw) > max_bytes:
        raise JSONInputError("response_limit")

    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > max_depth:
                raise JSONInputError("payload_limit")
        elif char in (93, 125):
            depth -= 1

    def pairs(items):
        value = {}
        for key, child in items:
            if key in value:
                raise JSONInputError("duplicate_key")
            value[key] = child
        return value

    def invalid_constant(_value):
        raise JSONInputError("invalid_json")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
        # The input bound and depth preflight bound parser allocations. This
        # final encoding rejects overflowed floats and unpaired Unicode surrogates.
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > max_bytes * 6:
            raise JSONInputError("payload_limit")
        return value
    except JSONInputError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise JSONInputError("invalid_json") from None
