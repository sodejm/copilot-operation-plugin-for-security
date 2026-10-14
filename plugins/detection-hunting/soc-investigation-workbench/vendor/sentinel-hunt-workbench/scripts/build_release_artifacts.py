"""Build the reproducible offline archive and local release evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from huntwb.errors import HuntWorkbenchError
from huntwb.release_build import build_release_artifacts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20260916)
    args = parser.parse_args()
    try:
        result = build_release_artifacts(args.seed)
    except HuntWorkbenchError as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return error.exit_code
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
