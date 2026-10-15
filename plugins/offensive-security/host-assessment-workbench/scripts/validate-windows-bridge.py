#!/usr/bin/env python3
"""Validate a native Windows bridge export, bound cleanup receipt, and empty canary root."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from host_assessment_workbench.core import ContractError  # noqa: E402
from host_assessment_workbench.windows_bridge import (  # noqa: E402
    load_bridge_receipt_bytes,
    validate_bridge_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("export", type=Path)
    parser.add_argument("--canary-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = validate_bridge_receipt(
            load_bridge_receipt_bytes(args.receipt.read_bytes()),
            args.export.read_bytes(),
            args.canary_root,
        )
    except (ContractError, OSError) as exc:
        print(f"Windows bridge validation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
