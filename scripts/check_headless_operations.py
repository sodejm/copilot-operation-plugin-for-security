"""Generate or validate operation metadata without loading execution payloads."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cops.operations.metadata import synchronize, validate_installed_metadata  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    if args.generate:
        synchronize()
    try:
        print(json.dumps(validate_installed_metadata(), sort_keys=True))
    except OSError, ValueError, TypeError, KeyError:
        print(json.dumps({"error": "invalid_or_stale_operation_metadata"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
