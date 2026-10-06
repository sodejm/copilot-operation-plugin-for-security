"""Shared fail-closed limits and descriptor-anchored reads for local evidence."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from ._runtime.cops.evidence.canonical import EvidenceError, decode_json


class IngestError(ValueError):
    """A stable code; source values and filesystem paths are never included."""


DEFAULTS = {"file_bytes": 4 * 1024 * 1024, "total_bytes": 64 * 1024 * 1024,
            "files": 64, "line_bytes": 1024 * 1024, "records": 50000, "json_depth": 32}
CEILINGS = {"file_bytes": 16 * 1024 * 1024, "total_bytes": 256 * 1024 * 1024,
            "files": 256, "line_bytes": 4 * 1024 * 1024, "records": 200000, "json_depth": 64}


@dataclass(frozen=True)
class Limits:
    file_bytes: int = DEFAULTS["file_bytes"]
    total_bytes: int = DEFAULTS["total_bytes"]
    files: int = DEFAULTS["files"]
    line_bytes: int = DEFAULTS["line_bytes"]
    records: int = DEFAULTS["records"]
    json_depth: int = DEFAULTS["json_depth"]

    @classmethod
    def from_values(cls, values=None, *, ceiling_values=None):
        merged = dict(DEFAULTS)
        for source in (values, ceiling_values):
            if source is None:
                continue
            if not isinstance(source, dict):
                raise IngestError("invalid_limit")
            for key, value in source.items():
                if key not in CEILINGS or type(value) is not int or not 0 < value <= CEILINGS[key]:
                    raise IngestError("invalid_limit")
        if values:
            merged.update(values)
        if ceiling_values:
            for key, value in ceiling_values.items():
                merged[key] = min(merged[key], value)
        return cls(**merged)

    def export(self):
        return {key: getattr(self, key) for key in DEFAULTS}


@dataclass
class RunBudget:
    limits: Limits
    bytes: int = 0
    files: int = 0
    records: int = 0
    lines: int = 0

    def add_records(self, amount=1):
        if type(amount) is not int or amount < 0 or self.records + amount > self.limits.records:
            raise IngestError("record_limit")
        self.records += amount

    def receipt(self):
        return {"limits": self.limits.export(), "bytes": self.bytes,
                "files": self.files, "records": self.records, "lines": self.lines}


@dataclass(frozen=True)
class FileRead:
    data: bytes
    identity: tuple[int, ...]


def _absolute_parts(root):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise IngestError("safe_reader_unavailable")
    parts = list(Path(os.path.abspath(root)).parts[1:])
    # macOS supplies these two fixed aliases for temporary and variable data.
    if parts and parts[0] in ("tmp", "var") and Path("/" + parts[0]).is_symlink():
        parts = ["private"] + parts
    return parts


def read_regular(root, relative, limit, budget: RunBudget | None = None, *, count_file=True) -> FileRead:
    if (not isinstance(relative, str) or not relative or len(relative) > 2048
            or relative.startswith("/") or "\\" in relative or any(ord(c) < 32 for c in relative)
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise IngestError("unsafe_path")
    if type(limit) is not int or limit <= 0 or limit > CEILINGS["file_bytes"]:
        raise IngestError("invalid_limit")
    parts = _absolute_parts(root) + relative.split("/")
    if budget is not None and count_file and budget.files >= budget.limits.files:
        raise IngestError("file_count_limit")
    remaining = budget.limits.total_bytes - budget.bytes if budget else limit
    if remaining < 0:
        raise IngestError("total_byte_limit")
    descriptors = []
    try:
        descriptors.append(os.open("/", os.O_RDONLY | os.O_DIRECTORY))
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(parts) - 1:
                flags |= os.O_DIRECTORY
            descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
        fd = descriptors[-1]
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise IngestError("nonregular_file")
        if before.st_nlink != 1:
            raise IngestError("unsafe_file")
        if before.st_size > limit:
            raise IngestError("file_limit")
        if before.st_size > remaining:
            raise IngestError("total_byte_limit")
        allowed = min(limit, remaining)
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, allowed + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > allowed:
                raise IngestError("file_limit" if limit <= remaining else "total_byte_limit")
            chunks.append(chunk)
        after = os.fstat(fd)
        def identity(item):
            return (item.st_dev, item.st_ino, item.st_nlink, item.st_size,
                                         item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after) or size != after.st_size:
            raise IngestError("file_changed")
        if budget:
            budget.bytes += size
            budget.files += int(count_file)
        return FileRead(b"".join(chunks), identity(after))
    except OSError:
        raise IngestError("unsafe_file") from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _check_array_cardinality(raw: bytes, path: tuple[str, ...], cap: int):
    """Scan JSON structure and stop before decoding a forbidden array element."""
    index = 0

    def spaces():
        nonlocal index
        while index < len(raw) and raw[index] in b" \t\r\n":
            index += 1

    def quoted(*, key=False):
        nonlocal index
        start = index
        if index >= len(raw) or raw[index] != 34:
            raise IngestError("invalid_json")
        index += 1
        escaped = False
        while index < len(raw):
            char = raw[index]
            index += 1
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                if key:
                    try:
                        return json.loads(raw[start:index])
                    except (ValueError, UnicodeDecodeError):
                        raise IngestError("invalid_json") from None
                return None
        raise IngestError("invalid_json")

    def value(current):
        nonlocal index
        spaces()
        if index >= len(raw):
            raise IngestError("invalid_json")
        char = raw[index]
        if char == 123:  # object
            index += 1
            spaces()
            if index < len(raw) and raw[index] == 125:
                index += 1
                return
            while True:
                key = quoted(key=True)
                spaces()
                if index >= len(raw) or raw[index] != 58:
                    raise IngestError("invalid_json")
                index += 1
                value(current + (key,))
                spaces()
                if index >= len(raw):
                    raise IngestError("invalid_json")
                separator = raw[index]
                index += 1
                if separator == 125:
                    return
                if separator != 44:
                    raise IngestError("invalid_json")
                spaces()
        elif char == 91:  # array
            index += 1
            spaces()
            if index < len(raw) and raw[index] == 93:
                index += 1
                return
            count = 0
            while True:
                count += 1
                if current == path and count > cap:
                    raise IngestError("record_limit")
                value(current + ("*",))
                spaces()
                if index >= len(raw):
                    raise IngestError("invalid_json")
                separator = raw[index]
                index += 1
                if separator == 93:
                    return
                if separator != 44:
                    raise IngestError("invalid_json")
                spaces()
        elif char == 34:
            quoted()
        else:
            start = index
            while index < len(raw) and raw[index] not in b" \t\r\n,]}":
                index += 1
            if start == index:
                raise IngestError("invalid_json")

    value(())
    spaces()
    if index != len(raw):
        raise IngestError("invalid_json")


def parse_json(raw: bytes, limits: Limits, *, max_bytes: int, record_cap: int | None = None,
               record_path: tuple[str, ...] = ("records",)):
    """Pre-scan depth before the recursive JSON decoder."""
    if len(raw) > max_bytes:
        raise IngestError("file_limit")
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
            continue
        if char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > limits.json_depth:
                raise IngestError("json_depth_limit")
        elif char in (93, 125):
            depth -= 1
    if record_cap is not None:
        _check_array_cardinality(raw, record_path, record_cap)
    try:
        value = decode_json(raw, max_bytes=max_bytes, max_depth=limits.json_depth)
    except EvidenceError as exc:
        raise IngestError("duplicate JSON key" if str(exc) == "duplicate_key" else "invalid_json") from None
    return value


def iter_jsonl(raw: bytes, limits: Limits, budget: RunBudget):
    """Yield logical lines without an unbounded splitlines allocation."""
    offset = 0
    while offset < len(raw):
        end = raw.find(b"\n", offset, min(len(raw), offset + limits.line_bytes + 2))
        if end < 0:
            if len(raw) - offset > limits.line_bytes:
                raise IngestError("line_limit")
            end = len(raw)
        if end - offset > limits.line_bytes:
            raise IngestError("line_limit")
        line = raw[offset:end]
        if line.endswith(b"\r"):
            line = line[:-1]
        budget.lines += 1
        yield line
        offset = end + 1
