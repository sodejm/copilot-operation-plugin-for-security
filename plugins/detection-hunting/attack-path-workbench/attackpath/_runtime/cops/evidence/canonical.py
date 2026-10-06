"""Bounded canonical JSON; error messages never include untrusted values."""
from datetime import datetime, timezone
import hashlib
import json
import math
import re


class EvidenceError(ValueError):
    def __init__(self, code="invalid_contract"):
        self.code = code
        super().__init__(code)


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value
    ):
        raise EvidenceError("invalid_timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError("invalid_timestamp") from None


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical(value, *, max_bytes=1024 * 1024, max_depth=32):
    if type(max_bytes) is not int or max_bytes <= 0 or type(max_depth) is not int or not 1 <= max_depth <= 64:
        raise EvidenceError("invalid_limit")
    # Pending depth is the number of enclosing containers. Count each container
    # before inspecting children so empty and populated containers have the same
    # depth, matching the streaming decoder's structural preflight.
    pending = [(value, 0)]
    nodes = 0
    minimum_bytes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        minimum_bytes += 1
        if nodes > max_bytes:
            raise EvidenceError("payload_limit")
        if type(item) is dict:
            container_depth = depth + 1
            if container_depth > max_depth:
                raise EvidenceError("payload_limit")
            minimum_bytes += 1
            if nodes + len(pending) + len(item) > max_bytes:
                raise EvidenceError("payload_limit")
            for key in item:
                if type(key) is not str:
                    raise EvidenceError("invalid_json")
                minimum_bytes += len(key) + 3
                if minimum_bytes > max_bytes:
                    raise EvidenceError("payload_limit")
            pending.extend((child, container_depth) for child in item.values())
        elif type(item) is list:
            container_depth = depth + 1
            if container_depth > max_depth:
                raise EvidenceError("payload_limit")
            minimum_bytes += 1
            if nodes + len(pending) + len(item) > max_bytes:
                raise EvidenceError("payload_limit")
            pending.extend((child, container_depth) for child in item)
        elif type(item) is float:
            if not math.isfinite(item):
                raise EvidenceError("invalid_json")
        elif type(item) is str:
            minimum_bytes += len(item) + 1
        elif type(item) is int:
            # Hexadecimal digit count bounds decimal size without converting a huge integer.
            minimum_bytes += max(1, (item.bit_length() + 3) // 4) - 1 + (item < 0)
        elif item is not None and type(item) not in (bool, int):
            raise EvidenceError("invalid_json")
        # Count a lower bound before allocating the complete JSON text. UTF-8 and
        # escapes can enlarge it; the exact byte check below remains authoritative.
        if minimum_bytes > max_bytes:
            raise EvidenceError("payload_limit")
    try:
        result = json.dumps(value, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceError("invalid_json") from None
    if len(result) > max_bytes:
        raise EvidenceError("payload_limit")
    return result


def digest(value, **limits):
    return hashlib.sha256(canonical(value, **limits)).hexdigest()


def decode_json(raw, *, max_bytes=4 * 1024 * 1024, max_depth=32):
    if type(max_bytes) is not int or max_bytes <= 0 or type(max_depth) is not int or not 1 <= max_depth <= 64:
        raise EvidenceError("invalid_limit")
    if type(raw) is not bytes or len(raw) > max_bytes:
        raise EvidenceError("response_limit")
    # Check depth before the recursive decoder; braces inside strings do not count.
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
                raise EvidenceError("payload_limit")
        elif char in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise EvidenceError("duplicate_key")
            result[key] = item
        return result

    def invalid_constant(_value):
        raise EvidenceError("invalid_json")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=invalid_constant)
        canonical(result, max_bytes=max_bytes * 6, max_depth=max_depth)
        return result
    except EvidenceError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceError("invalid_json") from None
