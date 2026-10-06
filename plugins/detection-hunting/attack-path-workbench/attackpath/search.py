"""Deterministic hard ceilings for offline path search and report serialization."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SearchLimits:
    expansions: int = 50_000
    frontier: int = 10_000
    complete_paths: int = 1_000
    partial_paths: int = 1_000
    emitted_paths: int = 100
    report_bytes: int = 64 * 1024 * 1024

    @classmethod
    def from_values(cls, values: dict[str, int] | None = None) -> SearchLimits:
        defaults = asdict(cls())
        if values is None:
            values = {}
        if not isinstance(values, dict) or values.keys() - defaults.keys():
            raise ValueError("unknown search limit")
        for key, value in values.items():
            if type(value) is not int or not 1 <= value <= defaults[key]:
                raise ValueError(f"{key}: search limit must be a positive integer no greater than {defaults[key]}")
        return cls(**values)

    def receipt_limits(self) -> dict[str, int]:
        return asdict(self)


def bounded_json_bytes(value: Any, limit: int) -> int:
    """Count the canonical JSON encoding without materializing an oversized copy."""
    import json

    size = 1  # canonical trailing newline
    for part in json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False).iterencode(value):
        size += len(part.encode("utf-8"))
        if size > limit:
            raise ValueError("report_byte_limit")
    return size
