#!/usr/bin/env python3
"""Validate a native Windows bridge export, bound cleanup receipt, and empty canary root."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from host_assessment_workbench.core import MAX_INPUT_BYTES, ContractError  # noqa: E402
from host_assessment_workbench.windows_bridge import (  # noqa: E402
    load_bridge_receipt_bytes,
    validate_bridge_receipt,
    validate_windows_existing_path,
)


def read_bounded_input(path: Path) -> bytes:
    with path.open("rb") as source:
        data = source.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ContractError(f"{path.name} exceeds the {MAX_INPUT_BYTES}-byte input limit")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("export", type=Path)
    parser.add_argument("--canary-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt_path = validate_windows_existing_path(args.receipt, "receipt")
        export_path = validate_windows_existing_path(args.export, "export")
        canary_root = validate_windows_existing_path(args.canary_root, "canary root")
        result = validate_bridge_receipt(
            load_bridge_receipt_bytes(read_bounded_input(receipt_path)),
            read_bounded_input(export_path),
            canary_root,
        )
    except (ContractError, OSError) as exc:
        print(f"Windows bridge validation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
