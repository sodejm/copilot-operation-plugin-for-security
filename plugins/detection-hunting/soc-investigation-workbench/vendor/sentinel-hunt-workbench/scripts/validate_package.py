"""Validate the complete offline distribution package."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from huntwb.errors import HuntWorkbenchError
from huntwb.package_validation import validate_package


def main() -> int:
    try:
        result = validate_package()
    except HuntWorkbenchError as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return error.exit_code
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
