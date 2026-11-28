#!/usr/bin/env python3
"""Package the reviewed public-domain single module without executing setup.py."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import zipfile
from pathlib import Path

SOURCE_SHA256 = "d781a43b0c16ace3f9366aade73e8ad3a7bd5137d58f0b45ab2d3f54876f20db"
DIST = "hexdump-3.3.dist-info"


def build(source: Path, destination: Path) -> Path:
    with source.open("rb") as stream:
        raw = stream.read(65_537)
    if len(raw) > 65_536 or hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("hexdump source does not match the reviewed release")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.getinfo("hexdump.py").file_size > 131_072:
            raise ValueError("hexdump module exceeds the reviewed size bound")
        module = archive.read("hexdump.py")
    files = {
        "hexdump.py": module,
        f"{DIST}/METADATA": b"Metadata-Version: 2.1\nName: hexdump\nVersion: 3.3\nLicense: Public Domain\nSummary: Reviewed upstream single module\n\n",
        f"{DIST}/WHEEL": b"Wheel-Version: 1.0\nGenerator: COPS reviewed-module-builder-v1\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    rows = [
        [
            name,
            "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(),
            str(len(data)),
        ]
        for name, data in sorted(files.items())
    ]
    rows.append([f"{DIST}/RECORD", "", ""])
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[f"{DIST}/RECORD"] = record.getvalue().encode()
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / "hexdump-3.3-py3-none-any.whl"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.external_attr = 0o100644 << 16
            entry.create_system = 3
            archive.writestr(entry, data)
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    target = build(args.source, args.destination)
    print(hashlib.sha256(target.read_bytes()).hexdigest())
