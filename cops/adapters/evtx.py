"""Registered bounded import of clean EVTX exports using an optional pinned parser."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import zlib
from datetime import datetime
from pathlib import Path

from .artifacts import artifact_adapter

ADAPTER = "sysmon-evtx/v1"
REGISTRATION = artifact_adapter(ADAPTER)
PARSER = REGISTRATION.prerequisites[0]
MAX_BYTES = REGISTRATION.max_bytes
MAX_RECORDS = REGISTRATION.max_records
MAX_OUTPUT = 2 * 1024 * 1024
ERRORS = frozenset(
    {
        "unsupported_parser_platform",
        "resource_boundary_unavailable",
        "parser_version_mismatch",
        "parser_unavailable",
        "record_limit",
        "parser_output_limit",
        "invalid_event_data",
    }
)


class EvtxImportError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise EvtxImportError(code)


def validate_evtx(raw: bytes, max_records: int = MAX_RECORDS) -> list[dict[str, int]]:
    """Reject unsupported recovery layouts and incomplete/corrupt record framing."""
    _require(4096 <= len(raw) <= MAX_BYTES and (len(raw) - 4096) % 65536 == 0, "invalid_file_size")
    _require(raw[:8] == b"ElfFile\0", "invalid_file_signature")
    first, last, next_id, header_size, minor, major, block_size, chunks = struct.unpack_from("<QQQIHHHH", raw, 8)
    _require(
        (major, minor) in {(3, 1), (3, 2)} and header_size == 128 and block_size == 4096, "unsupported_file_version"
    )
    _require(struct.unpack_from("<I", raw, 120)[0] == 0 and first == 0, "unsupported_recovery_layout")
    _require(zlib.crc32(raw[:120]) == struct.unpack_from("<I", raw, 124)[0], "file_header_checksum")
    _require(chunks > 0 and chunks == (len(raw) - 4096) // 65536 and last == chunks - 1, "invalid_chunk_count")
    records = []
    previous_id = 0
    for chunk_index in range(chunks):
        chunk = raw[4096 + chunk_index * 65536 : 4096 + (chunk_index + 1) * 65536]
        _require(chunk[:8] == b"ElfChnk\0", "invalid_chunk_signature")
        file_first, file_last, log_first, log_last, size, last_offset, free, checksum = struct.unpack_from(
            "<QQQQIIII", chunk, 8
        )
        _require(size == 128 and 512 <= last_offset < free <= 65536, "invalid_chunk_bounds")
        _require(zlib.crc32(chunk[512:free]) == checksum, "chunk_data_checksum")
        _require(
            zlib.crc32(chunk[:120] + chunk[128:512]) == struct.unpack_from("<I", chunk, 124)[0], "chunk_header_checksum"
        )
        start = len(records)
        offset, observed_last = 512, 0
        while offset < free:
            _require(len(records) < max_records, "record_limit")
            _require(offset + 28 <= free, "invalid_record_bounds")
            magic, length, record_id, _timestamp = struct.unpack_from("<IIQQ", chunk, offset)
            _require(
                magic == 0x2A2A and length >= 32 and length % 8 == 0 and offset + length <= free,
                "invalid_record_bounds",
            )
            _require(struct.unpack_from("<I", chunk, offset + length - 4)[0] == length, "record_size_mismatch")
            _require(record_id > previous_id, "invalid_record_identity")
            records.append({"record_id": record_id, "chunk": chunk_index, "offset": offset})
            previous_id = record_id
            observed_last, offset = offset, offset + length
        _require(offset == free and observed_last == last_offset, "invalid_record_bounds")
        count = len(records) - start
        _require(count > 0 and file_last >= file_first and file_last - file_first + 1 == count, "invalid_record_count")
        _require(
            log_first == records[start]["record_id"] and log_last == records[-1]["record_id"], "invalid_record_identity"
        )
    _require(next_id == previous_id + 1, "invalid_record_identity")
    return records


def _snapshot(path: Path, max_bytes: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            _require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), "source_not_regular")
            _require(before.st_size <= max_bytes, "input_size_limit")
            raw = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())

        def identity(info: os.stat_result) -> tuple[int, ...]:
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        _require(identity(before) == identity(after) and len(raw) == before.st_size, "source_changed")
        _require(len(raw) <= max_bytes, "input_size_limit")
        return raw
    except OSError as exc:
        raise EvtxImportError("source_not_regular") from exc


def _parse_snapshot(raw: bytes, max_records: int, deadline: float) -> dict:
    worker = Path(__file__).with_name("_evtx_worker.py")
    with tempfile.TemporaryDirectory(prefix="cops-evtx-") as directory:
        source, output = Path(directory) / "source.evtx", Path(directory) / "result.json"
        source.write_bytes(raw)
        source.chmod(0o400)
        try:
            with output.open("wb") as destination:
                result = subprocess.run(
                    [sys.executable, "-I", str(worker), str(source), str(max_records)],
                    cwd=directory,
                    env={},
                    stdin=subprocess.DEVNULL,
                    stdout=destination,
                    stderr=subprocess.DEVNULL,
                    timeout=deadline,
                    check=False,
                )
            _require(result.returncode == 0, "parser_failed")
            _require(output.stat().st_size <= MAX_OUTPUT, "parser_output_limit")
            with output.open("rb") as stream:
                data = json.loads(stream.read(MAX_OUTPUT + 1))
        except subprocess.TimeoutExpired as exc:
            raise EvtxImportError("parser_deadline") from exc
        except (OSError, ValueError) as exc:
            if isinstance(exc, EvtxImportError):
                raise
            raise EvtxImportError("parser_failed") from exc
    _require(isinstance(data, dict), "invalid_parser_result")
    if "error" in data:
        code = data["error"]
        raise EvtxImportError(code if isinstance(code, str) and code in ERRORS else "parser_failed")
    return data


def _validate_event(event: dict, record_id: int) -> None:
    _require(isinstance(event, dict), "invalid_parser_result")
    common = {"record_id", "event_id", "timestamp", "image_family"}
    event_id = event.get("event_id")
    _require(type(event_id) is int and event_id in {1, 3, 10}, "invalid_parser_result")
    fields = {
        1: {"encoded_command"},
        3: {"source_ip", "destination_ip"},
        10: {"target_is_lsass", "process_read_access"},
    }[event_id]
    _require(
        set(event) == common | fields and type(event.get("record_id")) is int and event["record_id"] == record_id,
        "invalid_parser_result",
    )
    _require(
        isinstance(event["image_family"], str)
        and event["image_family"] in {"powershell", "cmd", "notepad", "lsass", "other"},
        "invalid_parser_result",
    )
    try:
        stamp = event["timestamp"]
        _require(isinstance(stamp, str) and len(stamp) <= 32 and stamp.endswith("Z"), "invalid_parser_result")
        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        for field in fields:
            if field.endswith("_ip"):
                _require(
                    isinstance(event[field], str)
                    and "%" not in event[field]
                    and str(ipaddress.ip_address(event[field])) == event[field],
                    "invalid_parser_result",
                )
            else:
                _require(type(event[field]) is bool, "invalid_parser_result")
    except (ValueError, TypeError) as exc:
        raise EvtxImportError("invalid_parser_result") from exc


def import_evtx(
    path: Path,
    *,
    expected_sha256: str,
    max_bytes: int = MAX_BYTES,
    max_records: int = MAX_RECORDS,
    deadline: float = 10.0,
) -> dict:
    for value, upper in ((max_bytes, MAX_BYTES), (max_records, MAX_RECORDS)):
        _require(type(value) is int and 0 < value <= upper, "invalid_budget")
    _require(type(deadline) in {int, float} and math.isfinite(deadline) and 0 < deadline <= 10, "invalid_budget")
    _require(
        isinstance(expected_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
        "invalid_source_hash",
    )
    raw = _snapshot(path, max_bytes)
    digest = hashlib.sha256(raw).hexdigest()
    _require(digest == expected_sha256, "source_hash_mismatch")
    framing = validate_evtx(raw, max_records)
    parsed = _parse_snapshot(raw, max_records, deadline)
    rows = parsed.get("records")
    _require(
        set(parsed) == {"records"} and isinstance(rows, list) and len(rows) == len(framing), "parser_record_mismatch"
    )
    events, incomplete = [], {}
    for frame, row in zip(framing, rows, strict=True):
        _require(
            isinstance(row, dict) and type(row.get("record_id")) is int and row["record_id"] == frame["record_id"],
            "parser_record_mismatch",
        )
        if set(row) == {"record_id", "incomplete"}:
            reason = row["incomplete"]
            _require(
                isinstance(reason, str)
                and reason in {"missing_event_fields", "unsupported_provider", "unsupported_event_id"},
                "invalid_parser_result",
            )
            incomplete[reason] = incomplete.get(reason, 0) + 1
        else:
            _require(set(row) == {"record_id", "event"}, "invalid_parser_result")
            event = row["event"]
            _validate_event(event, frame["record_id"])
            events.append({**event, "evidence_ref": f"evtx:sha256:{digest}:record:{frame['record_id']}"})
    partial = bool(incomplete) or not events
    return {
        "schema_version": "cops.evtx-import/v1",
        "adapter": ADAPTER,
        "parser": PARSER,
        "status": "partial" if partial else "imported",
        "coverage_status": "indeterminate" if partial else "complete_supported_records",
        "source_sha256": digest,
        "records_total": len(framing),
        "records_normalized": len(events),
        "records_incomplete": len(framing) - len(events),
        "incomplete_reasons": incomplete,
        "events": events,
        "indicator_counts": {
            "powershell_network": sum(
                e["event_id"] == 3 and e["image_family"] == "powershell" and e["source_ip"] != e["destination_ip"]
                for e in events
            ),
            "encoded_command": sum(e.get("encoded_command", False) for e in events),
        },
        "limitations": [
            "Synthetic fixtures do not establish native Windows acquisition readiness.",
            "Indicators are observations, not verified malicious activity or proof of a clean host.",
            "Only clean, non-wrapped exports and Sysmon event IDs 1, 3, and 10 are supported.",
            "The parser process has resource limits; network isolation requires the laboratory runtime.",
        ],
    }
