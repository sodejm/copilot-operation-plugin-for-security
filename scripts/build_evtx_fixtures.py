#!/usr/bin/env python3
"""Build deterministic synthetic EVTX 3.1 files; never invoke submitted content."""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "cops/laboratory/service_fixtures"
STREAM = b"\x0f\x01\x01\x00"
TIMESTAMP = "2026-10-15T12:00:00.000000Z"
FILETIME = 134049168000000000


def name_string(name: str) -> bytes:
    digest = 0
    for char in name:
        digest = (digest * 37 + ord(char)) & 0xFFFF
    return struct.pack("<IHH", 0, digest, len(name)) + name.encode("utf-16le") + b"\0\0"


def value(text: str) -> bytes:
    return b"\x05\x01" + struct.pack("<H", len(text)) + text.encode("utf-16le")


def element(name: str, attributes: dict[str, str], children: list | str, offset: int) -> bytes:
    header_length = 15 if attributes else 11
    tag = name_string(name)
    position = offset + header_length + len(tag)
    attrs = bytearray()
    for key, text in attributes.items():
        entry = b"\x06" + struct.pack("<I", position + 5) + name_string(key) + value(text)
        attrs.extend(entry)
        position += len(entry)
    content = bytearray(b"\x02")
    position += 1
    if isinstance(children, str):
        content.extend(value(children))
    else:
        for child in children:
            entry = element(*child, position)
            content.extend(entry)
            position += len(entry)
    content.append(4)
    size = header_length + len(tag) + len(attrs) + len(content)
    header = struct.pack("<BHII", 0x41 if attributes else 1, 0, size - 7, offset + header_length)
    if attributes:
        header += struct.pack("<I", len(attrs))
    return header + tag + attrs + content


def record(event_id: int, data: dict[str, str], record_id: int, offset: int) -> bytes:
    system = ("System", {}, [
        ("Provider", {"Name": "Microsoft-Windows-Sysmon"}, []),
        ("EventID", {}, str(event_id)),
        ("TimeCreated", {"SystemTime": TIMESTAMP}, []),
        ("EventRecordID", {}, str(record_id)),
        ("Channel", {}, "Microsoft-Windows-Sysmon/Operational"),
    ])
    event_data = ("EventData", {}, [("Data", {"Name": key}, text) for key, text in data.items()])
    template_offset = offset + 24 + len(STREAM) + 10
    xml = STREAM + element("Event", {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
                           [system, event_data], template_offset + 24 + len(STREAM)) + b"\0"
    template = struct.pack("<II", 0, record_id) + b"\0" * 12 + struct.pack("<I", len(xml)) + xml
    binary_xml = STREAM + struct.pack("<BBII", 12, 0, record_id, template_offset) + template + b"\0" + struct.pack("<I", 0)
    size = (24 + len(binary_xml) + 4 + 7) & ~7
    return (struct.pack("<IIQQ", 0x2A2A, size, record_id, FILETIME) + binary_xml
            + b"\0" * (size - 28 - len(binary_xml)) + struct.pack("<I", size))


def build(events: list[tuple[int, dict[str, str]]]) -> bytes:
    chunk = bytearray(65536)
    chunk[:8] = b"ElfChnk\0"
    position, last = 512, 512
    for index, (event_id, data) in enumerate(events, 1):
        entry = record(event_id, data, index, position)
        last = position
        chunk[position:position + len(entry)] = entry
        position += len(entry)
    if position > 65536:
        raise ValueError("fixture exceeds one chunk")
    struct.pack_into("<QQQQIIII", chunk, 8, 1, len(events), 1, len(events), 128, last, position,
                     zlib.crc32(chunk[512:position]))
    struct.pack_into("<I", chunk, 124, zlib.crc32(chunk[:120] + chunk[128:512]))
    header = bytearray(4096)
    header[:8] = b"ElfFile\0"
    struct.pack_into("<QQQIHHHH", header, 8, 0, 0, len(events) + 1, 128, 1, 3, 4096, 1)
    struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
    return bytes(header + chunk)


def fixtures() -> dict[str, bytes]:
    common = {"User": "lab-user", "UtcTime": TIMESTAMP}
    return {
        "sysmon-vulnerable.evtx": build([
            (1, {**common, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "CommandLine": "powershell.exe -EncodedCommand SYNTHETIC_SECRET"}),
            (3, {**common, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "SourceIp": "192.0.2.10", "DestinationIp": "198.51.100.20"}),
        ]),
        "sysmon-corrected.evtx": build([
            (1, {**common, "Image": r"C:\Windows\System32\notepad.exe", "CommandLine": "notepad.exe"}),
            (3, {**common, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "SourceIp": "127.0.0.1", "DestinationIp": "127.0.0.1"}),
        ]),
        "sysmon-insufficient.evtx": build([(3, {**common, "Image": "powershell.exe"})]),
    }


if __name__ == "__main__":
    outputs = fixtures()
    for filename, raw in outputs.items():
        (ROOT / filename).write_bytes(raw)
    print(json.dumps({name: hashlib.sha256(raw).hexdigest() for name, raw in outputs.items()}, sort_keys=True))
