"""Bounded transport contracts, shared by the CLI and MCP adapter."""

from __future__ import annotations

import json
import math
from typing import Any

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 48
MAX_NODES = 100_000
STATES = ("succeeded", "needs_input", "blocked", "partial", "failed")


class OperationError(ValueError):
    """Content-free error code; never forward a payload exception's text."""

    def __init__(self, code: str, *, result=None):
        self.code = code
        self.result = result
        super().__init__(code)


def check_tree(value: Any) -> None:
    pending = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH:
            raise OperationError("structure_limit")
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise OperationError("invalid_json")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise OperationError("invalid_json")
        elif item is not None and type(item) not in (str, int, float, bool):
            raise OperationError("invalid_json")


def encode(value: Any) -> bytes:
    check_tree(value)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True).encode(
            "utf-8"
        )
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise OperationError("invalid_json") from exc
    if len(raw) > MAX_BYTES:
        raise OperationError("size_limit")
    return raw


def decode(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_BYTES:
        raise OperationError("size_limit")

    def pairs(items):
        document = {}
        for key, value in items:
            if key in document:
                raise OperationError("duplicate_key")
            document[key] = value
        return document

    def constant(_value):
        raise OperationError("invalid_json")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(result, dict):
            raise OperationError("expected_object")
        check_tree(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, OperationError):
            raise
        raise OperationError("invalid_json") from exc


RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "operation_id",
        "request_id",
        "status",
        "result",
        "error",
        "next_action",
        "limitations",
    ],
    "properties": {
        "schema_version": {"const": "cops.operation-result/v1"},
        "operation_id": {"type": ["string", "null"], "maxLength": 96},
        "request_id": {"type": ["string", "null"], "maxLength": 96},
        "status": {"enum": list(STATES)},
        "result": {"type": ["object", "null"]},
        "error": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code"],
                    "properties": {"code": {"type": "string", "maxLength": 96}},
                },
            ]
        },
        "next_action": {"type": ["string", "null"], "maxLength": 512},
        "limitations": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 512}},
    },
}


def response(operation_id=None, request_id=None, *, status="succeeded", result=None, code=None, next_action=None):
    return {
        "schema_version": "cops.operation-result/v1",
        "operation_id": operation_id,
        "request_id": request_id,
        "status": status,
        "result": result,
        "error": {"code": code} if code else None,
        "next_action": next_action,
        "limitations": [
            "Operations analyze supplied data offline and grant no execution authority.",
            "Inputs must already be classified and redacted; this interface is not a DLP filter.",
        ],
    }
