#!/usr/bin/env python3
"""Generate the explicit portable evidence allowlist, never transport or credentials."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = Path("plugins/detection-hunting/attack-path-workbench/attackpath/_runtime")
SOURCES = tuple(
    "cops/evidence/" + name + ".py"
    for name in ("__init__", "canonical", "contract", "validation", "assessment", "ai_inventory")
) + ("catalog/schemas/evidence-envelope.schema.json", "catalog/schemas/acquisition-receipt.schema.json")


def generate(root=ROOT, *, check=False, destination=None):
    destination = destination or root / TARGET
    expected = {path: (root / path).read_bytes() for path in SOURCES}
    expected.update(
        {
            "__init__.py": b'"""Generated portable contracts. See source-manifest.json."""\n',
            "cops/__init__.py": b'"""Portable evidence namespace; generated."""\n',
        }
    )
    manifest = {
        "schema_version": "attackpath.sdk-bundle/v1",
        "contracts": ["cops.evidence/v1", "cops.acquisition/v1"],
        "sources": [{"path": name, "sha256": hashlib.sha256(expected[name]).hexdigest()} for name in SOURCES],
    }
    expected["source-manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    if check:
        return all(
            (destination / name).is_file() and (destination / name).read_bytes() == value
            for name, value in expected.items()
        ) and not any(
            p.is_file() and p.relative_to(destination).as_posix() not in expected
            for p in destination.rglob("*")
            if "__pycache__" not in p.parts
        )
    for name, value in expected.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not generate(check=args.check):
        parser.exit(1, "portable evidence bundle differs; run scripts/agent/bundle_evidence.py\n")
